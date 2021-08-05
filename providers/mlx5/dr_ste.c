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

#include "mlx5dv_dr.h"
#include "dr_ste.h"

struct dr_hw_ste_format {
	uint8_t ctrl[DR_STE_SIZE_CTRL];
	uint8_t tag[DR_STE_SIZE_TAG];
	uint8_t mask[DR_STE_SIZE_MASK];
};

uint32_t dr_ste_calc_hash_index(uint8_t *hw_ste_p, struct dr_ste_htbl *htbl)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	uint8_t masked[DR_STE_SIZE_TAG] = {};
	uint32_t crc32, index;
	uint8_t *p_masked;
	uint16_t bit;
	size_t len;
	int i;

	/* Don't calculate CRC if the result is predicted */
	if (htbl->chunk->num_of_entries == 1)
		return 0;

	if (htbl->type == DR_STE_HTBL_TYPE_LEGACY) {
		if (htbl->byte_mask == 0)
			return 0;

		len = DR_STE_SIZE_TAG;
		/* Mask tag using byte mask, bit per byte */
		bit = 1 << (DR_STE_SIZE_TAG - 1);
		for (i = 0; i < DR_STE_SIZE_TAG; i++) {
			if (htbl->byte_mask & bit)
				masked[i] = hw_ste->tag[i];

			bit = bit >> 1;
		}
		p_masked = masked;
	} else {
		len = DR_STE_SIZE_MATCH_TAG;
		p_masked = hw_ste->tag;
	}

	crc32 = dr_crc32_slice8_calc(p_masked, len);
	index = crc32 % htbl->chunk->num_of_entries;

	return index;
}

uint16_t dr_ste_conv_bit_to_byte_mask(uint8_t *bit_mask)
{
	uint16_t byte_mask = 0;
	int i;

	for (i = 0; i < DR_STE_SIZE_MASK; i++) {
		byte_mask = byte_mask << 1;
		if (bit_mask[i] == 0xff)
			byte_mask |= 1;
	}
	return byte_mask;
}

static uint8_t *dr_ste_get_tag(uint8_t *hw_ste_p)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;

	return hw_ste->tag;
}

void dr_ste_set_bit_mask(uint8_t *hw_ste_p, struct dr_ste_build *sb)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;

	if (sb->htbl_type == DR_STE_HTBL_TYPE_LEGACY)
		memcpy(hw_ste->mask, sb->bit_mask, DR_STE_SIZE_MASK);
}

static void dr_ste_set_always_hit(struct dr_hw_ste_format *hw_ste)
{
	memset(&hw_ste->tag, 0, sizeof(hw_ste->tag));
	memset(&hw_ste->mask, 0, sizeof(hw_ste->mask));
}

static void dr_ste_set_always_miss(struct dr_hw_ste_format *hw_ste)
{
	hw_ste->tag[0] = 0xdc;
	hw_ste->mask[0] = 0;
}

void dr_ste_set_miss_addr(struct dr_ste_ctx *ste_ctx, uint8_t *hw_ste_p,
			  uint64_t miss_addr)
{
	ste_ctx->set_miss_addr(hw_ste_p, miss_addr);
}

static void dr_ste_always_miss_addr(struct dr_ste_ctx *ste_ctx,
				    struct dr_ste *ste,
				    uint64_t miss_addr,
				    uint16_t gvmi)
{
	uint8_t *hw_ste_p = ste->hw_ste;

	ste_ctx->set_ctrl_always_miss(hw_ste_p, miss_addr, gvmi);

	dr_ste_set_always_miss((struct dr_hw_ste_format *)ste->hw_ste);
}

void dr_ste_set_hit_addr(struct dr_ste_ctx *ste_ctx, uint8_t *hw_ste_p,
			 uint64_t icm_addr, uint32_t ht_size)
{
	ste_ctx->set_hit_addr(hw_ste_p, icm_addr, ht_size);
}

void dr_ste_set_hit_gvmi(struct dr_ste_ctx *ste_ctx, uint8_t *hw_ste_p,
			 uint16_t gvmi)
{
	ste_ctx->set_hit_gvmi(hw_ste_p, gvmi);
}

uint64_t dr_ste_get_icm_addr(struct dr_ste *ste)
{
	uint32_t index = ste - ste->htbl->ste_arr;

	return dr_icm_pool_get_chunk_icm_addr(ste->htbl->chunk) +
	       DR_STE_SIZE * index;
}

uint64_t dr_ste_get_mr_addr(struct dr_ste *ste)
{
	uint32_t index = ste - ste->htbl->ste_arr;

	return dr_icm_pool_get_chunk_mr_addr(ste->htbl->chunk) +
	       DR_STE_SIZE * index;
}

struct list_head *dr_ste_get_miss_list(struct dr_ste *ste)
{
	uint32_t index = ste - ste->htbl->ste_arr;

	return &ste->htbl->miss_list[index];
}

struct dr_ste *dr_ste_get_miss_list_top(struct dr_ste *ste)
{
	/* Optimize miss list access (reduce cache misses) by checking
	 * if we actually need to jump to list_top:
	 * if number of entries in current hash table is more than one,
	 * it means that this is not a collision entry.
	 */

	if (ste->htbl->chunk->num_of_entries > 1)
		return ste;
	else
		return list_top(dr_ste_get_miss_list(ste),
				struct dr_ste, miss_list_node);
}

static void dr_ste_always_hit_htbl(struct dr_ste_ctx *ste_ctx,
				   struct dr_ste *ste,
				   struct dr_ste_htbl *next_htbl,
				   uint16_t gvmi)
{
	struct dr_icm_chunk *chunk = next_htbl->chunk;
	uint8_t *hw_ste = ste->hw_ste;

	ste_ctx->set_ctrl_always_hit_htbl(hw_ste,
					  next_htbl->byte_mask,
					  next_htbl->lu_type,
					  dr_icm_pool_get_chunk_icm_addr(chunk),
					  chunk->num_of_entries,
					  gvmi);

	dr_ste_set_always_hit((struct dr_hw_ste_format *)ste->hw_ste);
}

bool dr_ste_is_last_in_rule(struct dr_matcher_rx_tx *nic_matcher,
			    uint8_t ste_location)
{
	return ste_location == nic_matcher->num_of_builders;
}

/*
 * Replace relevant fields, except of:
 * htbl - keep the origin htbl
 * miss_list + list - already took the src from the list.
 * icm_addr/mr_addr - depends on the hosting table.
 *
 * Before:
 * | a | -> | b | -> | c | ->
 *
 * After:
 * | a | -> | c | ->
 * While the data that was in b copied to a.
 */
static void dr_ste_replace(struct dr_ste *dst, struct dr_ste *src)
{
	memcpy(dst->hw_ste, src->hw_ste, dst->size);
	dst->next_htbl = src->next_htbl;
	if (dst->next_htbl)
		dst->next_htbl->pointing_ste = dst;

	atomic_init(&dst->refcount, atomic_load(&src->refcount));
}

/* Free ste which is the head and the only one in miss_list */
static void
dr_ste_remove_head_ste(struct dr_ste_ctx *ste_ctx,
		       struct mlx5dv_dr_domain *dmn,
		       struct dr_ste *ste,
		       struct dr_matcher_rx_tx *nic_matcher,
		       struct dr_ste_send_info *ste_info_head,
		       struct list_head *send_ste_list,
		       struct dr_ste_htbl *stats_tbl)
{
	struct dr_domain_rx_tx *nic_dmn = nic_matcher->nic_tbl->nic_dmn;
	uint8_t formated_ste[DR_STE_SIZE] = {};
	struct dr_htbl_connect_info info;

	stats_tbl->ctrl.num_of_valid_entries--;

	/* Hash table will be deleted, no need to update STE */
	if (atomic_load(&ste->htbl->refcount) == 1)
		return;

	info.type = CONNECT_MISS;
	info.miss_icm_addr =
		dr_icm_pool_get_chunk_icm_addr(nic_matcher->e_anchor->chunk);
	dr_ste_set_formated_ste(ste_ctx,
				dmn->info.caps.gvmi,
				nic_dmn->type,
				ste->htbl,
				formated_ste,
				&info);
	memcpy(ste->hw_ste, formated_ste, ste->size);

	list_del_init(&ste->miss_list_node);

	/* Write full STE size in order to have "always_miss" */
	dr_send_fill_and_append_ste_send_info(ste, DR_STE_SIZE,
					      0, formated_ste,
					      ste_info_head,
					      send_ste_list,
					      true /* Copy data */);
}

/*
 * Free ste which is the head but NOT the only one in miss_list:
 * |_ste_| --> |_next_ste_| -->|__| -->|__| -->/0
 */
static void
dr_ste_replace_head_ste(struct dr_matcher_rx_tx *nic_matcher,
			struct dr_ste *ste, struct dr_ste *next_ste,
			struct dr_ste_send_info *ste_info_head,
			struct list_head *send_ste_list,
			struct dr_ste_htbl *stats_tbl)

{
	struct dr_ste_htbl *next_miss_htbl;
	uint8_t hw_ste[DR_STE_SIZE] = {};
	struct dr_ste_build *sb;
	int sb_idx;

	next_miss_htbl = next_ste->htbl;

	/* Remove from the miss_list the next_ste before copy */
	list_del_init(&next_ste->miss_list_node);

	/* Move data from next into ste */
	dr_ste_replace(ste, next_ste);

	/* Update the rule on STE change */
	dr_rule_set_last_member(next_ste->rule_rx_tx, ste, false);

	sb_idx = ste->ste_chain_location - 1;
	sb = &nic_matcher->ste_builder[sb_idx];

	/* Copy all 64 hw_ste bytes */
	memcpy(hw_ste, ste->hw_ste, ste->size);
	dr_ste_set_bit_mask(hw_ste, sb);

	/*
	 * Del the htbl that contains the next_ste.
	 * The origin htbl stay with the same number of entries.
	 */
	dr_htbl_put(next_miss_htbl);

	dr_send_fill_and_append_ste_send_info(ste, DR_STE_SIZE,
					      0, hw_ste,
					      ste_info_head,
					      send_ste_list,
					      true /* Copy data */);

	stats_tbl->ctrl.num_of_collisions--;
	stats_tbl->ctrl.num_of_valid_entries--;
}

/*
 * Free ste that is located in the middle of the miss list:
 * |__| -->|_prev_ste_|->|_ste_|-->|_next_ste_|
 */
static void dr_ste_remove_middle_ste(struct dr_ste_ctx *ste_ctx,
				     struct dr_ste *ste,
				     struct dr_ste_send_info *ste_info,
				     struct list_head *send_ste_list,
				     struct dr_ste_htbl *stats_tbl)
{
	struct dr_ste *prev_ste;
	uint64_t miss_addr;

	prev_ste = list_prev(dr_ste_get_miss_list(ste), ste, miss_list_node);
	assert(prev_ste);

	miss_addr = ste_ctx->get_miss_addr(ste->hw_ste);
	ste_ctx->set_miss_addr(prev_ste->hw_ste, miss_addr);

	dr_send_fill_and_append_ste_send_info(prev_ste, DR_STE_SIZE_CTRL, 0,
					      prev_ste->hw_ste, ste_info,
					      send_ste_list, true /* Copy data*/);

	list_del_init(&ste->miss_list_node);

	stats_tbl->ctrl.num_of_valid_entries--;
	stats_tbl->ctrl.num_of_collisions--;
}

void dr_ste_free(struct dr_ste *ste,
		 struct mlx5dv_dr_rule *rule,
		 struct dr_rule_rx_tx *nic_rule)
{
	struct dr_matcher_rx_tx *nic_matcher = nic_rule->nic_matcher;
	struct dr_ste_send_info *cur_ste_info, *tmp_ste_info;
	struct mlx5dv_dr_matcher *matcher = rule->matcher;
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	struct dr_ste_ctx *ste_ctx = dmn->ste_ctx;
	struct dr_ste_send_info ste_info_head;
	struct dr_ste *next_ste, *first_ste;
	bool put_on_origin_table = true;
	struct dr_ste_htbl *stats_tbl;
	LIST_HEAD(send_ste_list);

	first_ste = dr_ste_get_miss_list_top(ste);
	stats_tbl = first_ste->htbl;
	/*
	 * Two options:
	 * 1. ste is head:
	 *	a. head ste is the only ste in the miss list
	 *	b. head ste is not the only ste in the miss-list
	 * 2. ste is not head
	 */
	if (first_ste == ste) { /* Ste is the head */
		next_ste = list_next(dr_ste_get_miss_list(ste), ste, miss_list_node);
		if (!next_ste) {
			/* One and only entry in the list */
			dr_ste_remove_head_ste(ste_ctx, dmn, ste,
					       nic_matcher,
					       &ste_info_head,
					       &send_ste_list,
					       stats_tbl);
		} else {
			/* First but not only entry in the list */
			dr_ste_replace_head_ste(nic_matcher, ste, next_ste,
						&ste_info_head, &send_ste_list,
						stats_tbl);
			put_on_origin_table = false;
		}
	} else { /* Ste in the middle of the list */
		dr_ste_remove_middle_ste(ste_ctx, ste, &ste_info_head,
					 &send_ste_list, stats_tbl);
	}

	/* Update HW */
	list_for_each_safe(&send_ste_list, cur_ste_info, tmp_ste_info, send_list) {
		list_del(&cur_ste_info->send_list);
		dr_send_postsend_ste(dmn, cur_ste_info->ste,
				     cur_ste_info->data,
				     cur_ste_info->size,
				     cur_ste_info->offset,
				     nic_rule->lock_index);
	}

	if (put_on_origin_table)
		dr_htbl_put(ste->htbl);
}

bool dr_ste_equal_tag(void *src, void *dst, uint8_t tag_size)
{
	struct dr_hw_ste_format *s_hw_ste = (struct dr_hw_ste_format *)src;
	struct dr_hw_ste_format *d_hw_ste = (struct dr_hw_ste_format *)dst;

	return !memcmp(s_hw_ste->tag, d_hw_ste->tag, tag_size);
}

void dr_ste_set_hit_addr_by_next_htbl(struct dr_ste_ctx *ste_ctx,
				      uint8_t *hw_ste,
				      struct dr_ste_htbl *next_htbl)
{
	struct dr_icm_chunk *chunk = next_htbl->chunk;

	ste_ctx->set_hit_addr(hw_ste,
			      dr_icm_pool_get_chunk_icm_addr(chunk),
			      chunk->num_of_entries);
}

void dr_ste_prepare_for_postsend(struct dr_ste_ctx *ste_ctx,
				 uint8_t *hw_ste_p, uint32_t ste_size)
{
	if (ste_ctx->prepare_for_postsend)
		ste_ctx->prepare_for_postsend(hw_ste_p, ste_size);
}

/* Init one ste as a pattern for ste data array */
void dr_ste_set_formated_ste(struct dr_ste_ctx *ste_ctx,
			     uint16_t gvmi,
			     enum dr_domain_nic_type nic_type,
			     struct dr_ste_htbl *htbl,
			     uint8_t *formated_ste,
			     struct dr_htbl_connect_info *connect_info)
{
	bool is_rx = nic_type == DR_DOMAIN_NIC_TYPE_RX;
	struct dr_ste ste = {};

	ste_ctx->ste_init(formated_ste, htbl->lu_type, is_rx, gvmi);
	ste.hw_ste = formated_ste;

	if (connect_info->type == CONNECT_HIT)
		dr_ste_always_hit_htbl(ste_ctx, &ste, connect_info->hit_next_htbl, gvmi);
	else
		dr_ste_always_miss_addr(ste_ctx, &ste, connect_info->miss_icm_addr, gvmi);
}

int dr_ste_htbl_init_and_postsend(struct mlx5dv_dr_domain *dmn,
				  struct dr_domain_rx_tx *nic_dmn,
				  struct dr_ste_htbl *htbl,
				  struct dr_htbl_connect_info *connect_info,
				  bool update_hw_ste,
				  uint8_t send_ring_idx)
{
	uint8_t formated_ste[DR_STE_SIZE] = {};

	dr_ste_set_formated_ste(dmn->ste_ctx,
				dmn->info.caps.gvmi,
				nic_dmn->type,
				htbl,
				formated_ste,
				connect_info);

	return dr_send_postsend_formated_htbl(dmn, htbl, formated_ste,
					      update_hw_ste, send_ring_idx);
}

int dr_ste_create_next_htbl(struct mlx5dv_dr_matcher *matcher,
			    struct dr_matcher_rx_tx *nic_matcher,
			    struct dr_ste *ste,
			    uint8_t *cur_hw_ste,
			    enum dr_icm_chunk_size log_table_size,
			    uint8_t send_ring_idx)
{
	struct dr_domain_rx_tx *nic_dmn = nic_matcher->nic_tbl->nic_dmn;
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	struct dr_ste_ctx *ste_ctx = dmn->ste_ctx;
	struct dr_htbl_connect_info info;
	struct dr_ste_htbl *next_htbl;

	if (!dr_ste_is_last_in_rule(nic_matcher, ste->ste_chain_location)) {
		uint16_t next_lu_type;
		uint16_t byte_mask;

		next_lu_type = ste_ctx->get_next_lu_type(cur_hw_ste);
		byte_mask = ste_ctx->get_byte_mask(cur_hw_ste);

		next_htbl = dr_ste_htbl_alloc(dmn->ste_icm_pool,
					      log_table_size,
					      ste->htbl->type,
					      next_lu_type,
					      byte_mask);
		if (!next_htbl) {
			dr_dbg(dmn, "Failed allocating next hash table\n");
			return errno;
		}

		/* Write new table to HW */
		info.type = CONNECT_MISS;
		info.miss_icm_addr =
			dr_icm_pool_get_chunk_icm_addr(nic_matcher->e_anchor->chunk);
		if (dr_ste_htbl_init_and_postsend(dmn, nic_dmn, next_htbl,
						  &info, false, send_ring_idx)) {
			dr_dbg(dmn, "Failed writing table to HW\n");
			goto free_table;
		}

		dr_ste_set_hit_addr_by_next_htbl(ste_ctx, cur_hw_ste, next_htbl);
		ste->next_htbl = next_htbl;
		next_htbl->pointing_ste = ste;
	}

	return 0;

free_table:
	dr_ste_htbl_free(next_htbl);
	return ENOENT;
}

struct dr_ste_htbl *dr_ste_htbl_alloc(struct dr_icm_pool *pool,
				      enum dr_icm_chunk_size chunk_size,
				      enum dr_ste_htbl_type type,
				      uint16_t lu_type, uint16_t byte_mask)
{
	struct dr_icm_chunk *chunk;
	struct dr_ste_htbl *htbl;
	uint8_t ste_size;
	int i;

	htbl = calloc(1, sizeof(struct dr_ste_htbl));
	if (!htbl) {
		errno = ENOMEM;
		return NULL;
	}

	chunk = dr_icm_alloc_chunk(pool, chunk_size);
	if (!chunk)
		goto out_free_htbl;

	if (type == DR_STE_HTBL_TYPE_LEGACY)
		ste_size = DR_STE_SIZE_REDUCED;
	else
		ste_size = DR_STE_SIZE;

	htbl->type = type;
	htbl->chunk = chunk;
	htbl->lu_type = lu_type;
	htbl->byte_mask = byte_mask;
	htbl->ste_arr = chunk->ste_arr;
	htbl->hw_ste_arr = chunk->hw_ste_arr;
	htbl->miss_list = chunk->miss_list;
	atomic_init(&htbl->refcount, 0);

	for (i = 0; i < chunk->num_of_entries; i++) {
		struct dr_ste *ste = &htbl->ste_arr[i];

		ste->hw_ste = htbl->hw_ste_arr + i * ste_size;
		ste->htbl = htbl;
		ste->size = ste_size;
		atomic_init(&ste->refcount, 0);
		list_node_init(&ste->miss_list_node);
		list_head_init(&htbl->miss_list[i]);
		ste->next_htbl = NULL;
		ste->rule_rx_tx = NULL;
		ste->ste_chain_location = 0;
	}

	htbl->chunk_size = chunk_size;

	return htbl;

out_free_htbl:
	free(htbl);
	return NULL;
}

int dr_ste_htbl_free(struct dr_ste_htbl *htbl)
{
	if (atomic_load(&htbl->refcount))
		return EBUSY;

	dr_icm_free_chunk(htbl->chunk);
	free(htbl);
	return 0;
}

void dr_ste_set_actions_tx(struct dr_ste_ctx *ste_ctx,
			   uint8_t *action_type_set,
			   uint8_t *hw_ste_arr,
			   struct dr_ste_actions_attr *attr,
			   uint32_t *added_stes)
{
	ste_ctx->set_actions_tx(action_type_set, ste_ctx->actions_caps,
				hw_ste_arr, attr, added_stes);
}

void dr_ste_set_actions_rx(struct dr_ste_ctx *ste_ctx,
			   uint8_t *action_type_set,
			   uint8_t *hw_ste_arr,
			   struct dr_ste_actions_attr *attr,
			   uint32_t *added_stes)
{
	ste_ctx->set_actions_rx(action_type_set, ste_ctx->actions_caps,
				hw_ste_arr, attr, added_stes);
}

const struct dr_ste_action_modify_field *
dr_ste_conv_modify_hdr_sw_field(struct dr_ste_ctx *ste_ctx,
				struct dr_devx_caps *caps,
				uint16_t sw_field)
{
	return ste_ctx->get_action_hw_field(ste_ctx, sw_field, caps);
}

void dr_ste_set_action_set(struct dr_ste_ctx *ste_ctx,
			   __be64 *hw_action,
			   uint8_t hw_field,
			   uint8_t shifter,
			   uint8_t length,
			   uint32_t data)
{
	ste_ctx->set_action_set((uint8_t *)hw_action,
				hw_field, shifter, length, data);
}

void dr_ste_set_action_add(struct dr_ste_ctx *ste_ctx,
			   __be64 *hw_action,
			   uint8_t hw_field,
			   uint8_t shifter,
			   uint8_t length,
			   uint32_t data)
{
	ste_ctx->set_action_add((uint8_t *)hw_action,
				hw_field, shifter, length, data);
}

void dr_ste_set_action_copy(struct dr_ste_ctx *ste_ctx,
			    __be64 *hw_action,
			    uint8_t dst_hw_field,
			    uint8_t dst_shifter,
			    uint8_t dst_len,
			    uint8_t src_hw_field,
			    uint8_t src_shifter)
{
	ste_ctx->set_action_copy((uint8_t *)hw_action,
				 dst_hw_field, dst_shifter, dst_len,
				 src_hw_field, src_shifter);
}

int dr_ste_set_action_decap_l3_list(struct dr_ste_ctx *ste_ctx,
				    void *data, uint32_t data_sz,
				    uint8_t *hw_action, uint32_t hw_action_sz,
				    uint16_t *used_hw_action_num)
{
	/* Only Ethernet frame is supported, with VLAN (18) or without (14) */
	if (data_sz != HDR_LEN_L2 && data_sz != HDR_LEN_L2_W_VLAN) {
		errno = EINVAL;
		return errno;
	}

	return ste_ctx->set_action_decap_l3_list(data, data_sz,
						 hw_action, hw_action_sz,
						 used_hw_action_num);
}

static int dr_ste_alloc_modify_hdr_chunk(struct mlx5dv_dr_action *action,
					 uint32_t chunck_size)
{
	int ret;

	action->rewrite.param.chunk = dr_icm_alloc_chunk(action->rewrite.dmn->action_icm_pool,
							 chunck_size);
	if (!action->rewrite.param.chunk)
		return ENOMEM;

	action->rewrite.param.index =
		(dr_icm_pool_get_chunk_icm_addr(action->rewrite.param.chunk) -
		 action->rewrite.dmn->info.caps.hdr_modify_icm_addr) /
		ACTION_CACHE_LINE_SIZE;

	ret = dr_send_postsend_action(action->rewrite.dmn, action);
	if (ret)
		goto free_chunk;

	return 0;

free_chunk:
	dr_icm_free_chunk(action->rewrite.param.chunk);
	return ret;
}

static void dr_dealloc_modify_hdr_chunk(struct mlx5dv_dr_action *action)
{
	dr_icm_free_chunk(action->rewrite.param.chunk);
}

int dr_ste_alloc_modify_hdr(struct mlx5dv_dr_action *action)
{
	uint32_t dynamic_chunck_size;

	dynamic_chunck_size = ilog32(action->rewrite.param.num_of_actions - 1);

	/* HW modify action index granularity is at least 64B */
	dynamic_chunck_size = max_t(uint32_t, dynamic_chunck_size,
				    DR_CHUNK_SIZE_8);

	if (action->rewrite.dmn->modify_header_ptrn_mngr)
		return action->rewrite.dmn->ste_ctx->alloc_modify_hdr_chunk(action, dynamic_chunck_size);

	return dr_ste_alloc_modify_hdr_chunk(action, dynamic_chunck_size);
}

void dr_ste_free_modify_hdr(struct mlx5dv_dr_action *action)
{
	if (action->rewrite.dmn->modify_header_ptrn_mngr)
		return action->rewrite.dmn->ste_ctx->dealloc_modify_hdr_chunk(action);

	return dr_dealloc_modify_hdr_chunk(action);
}

int dr_ste_alloc_encap(struct mlx5dv_dr_action *action)
{
	struct mlx5dv_dr_domain *dmn = action->reformat.dmn;
	uint32_t dynamic_chunck_size;
	int ret;

	dynamic_chunck_size = ilog32((action->reformat.reformat_size - 1) /
				     DR_SW_ENCAP_ENTRY_SIZE);
	action->reformat.chunk = dr_icm_alloc_chunk(dmn->encap_icm_pool,
						    dynamic_chunck_size);
	if (!action->reformat.chunk)
		return errno;

	action->reformat.index = (dr_icm_pool_get_chunk_icm_addr(action->reformat.chunk) -
				  dmn->info.caps.indirect_encap_icm_base) /
				  DR_SW_ENCAP_ENTRY_SIZE;

	ret = dr_send_postsend_action(dmn, action);
	if (ret)
		goto postsend_err;

	return 0;

postsend_err:
	dr_icm_free_chunk(action->reformat.chunk);
	action->reformat.chunk = NULL;
	action->reformat.index = 0;

	return ret;
}

void dr_ste_free_encap(struct mlx5dv_dr_action *action)
{
	dr_icm_free_chunk(action->reformat.chunk);
}

static int dr_ste_build_pre_check_spec(struct mlx5dv_dr_domain *dmn,
				       struct dr_match_spec *m_spec,
				       struct dr_match_spec *v_spec)
{
	if (m_spec->ip_version) {
		if (m_spec->ip_version != 4 && m_spec->ip_version != 6) {
			dr_dbg(dmn, "IP version must be specified v4 or v6\n");
			errno = EOPNOTSUPP;
			return errno;
		}

		if (v_spec && (v_spec->ip_version != m_spec->ip_version)) {
			dr_dbg(dmn, "Mask and value IP version must be equal\n");
			errno = EOPNOTSUPP;
			return errno;
		}
	}
	return 0;
}

int dr_ste_build_pre_check(struct mlx5dv_dr_domain *dmn,
			   uint8_t match_criteria,
			   struct dr_match_param *mask,
			   struct dr_match_param *value)
{
	int ret;

	if (match_criteria & DR_MATCHER_CRITERIA_OUTER) {
		ret = dr_ste_build_pre_check_spec(dmn,
						  &mask->outer,
						  value ? &value->outer : NULL);
		if (ret)
			return ret;
	}

	if (match_criteria & DR_MATCHER_CRITERIA_INNER) {
		ret = dr_ste_build_pre_check_spec(dmn,
						  &mask->inner,
						  value ? &value->inner : NULL);
		if (ret)
			return ret;
	}

	if (!value && (match_criteria & DR_MATCHER_CRITERIA_MISC)) {
		if (mask->misc.source_port && mask->misc.source_port != 0xffff) {
			dr_dbg(dmn, "Partial mask source_port is not supported\n");
			errno = ENOTSUP;
			return errno;
		}
	}

	return 0;
}

int dr_ste_build_ste_arr(struct mlx5dv_dr_matcher *matcher,
			 struct dr_matcher_rx_tx *nic_matcher,
			 struct dr_match_param *value,
			 uint8_t *ste_arr)
{
	struct dr_domain_rx_tx *nic_dmn = nic_matcher->nic_tbl->nic_dmn;
	bool is_rx = nic_dmn->type == DR_DOMAIN_NIC_TYPE_RX;
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	struct dr_ste_ctx *ste_ctx = dmn->ste_ctx;
	struct dr_ste_build *sb;
	int ret, i;

	ret = dr_ste_build_pre_check(dmn, matcher->match_criteria,
				     &matcher->mask, value);
	if (ret)
		return ret;

	sb = nic_matcher->ste_builder;
	for (i = 0; i < nic_matcher->num_of_builders; i++) {
		ste_ctx->ste_init(ste_arr,
				  sb->lu_type,
				  is_rx,
				  dmn->info.caps.gvmi);

		dr_ste_set_bit_mask(ste_arr, sb);

		ret = sb->ste_build_tag_func(value, sb, dr_ste_get_tag(ste_arr));
		if (ret)
			return ret;

		/* Connect the STEs */
		if (i < (nic_matcher->num_of_builders - 1)) {
			/* Need the next builder for these fields,
			 * not relevant for the last ste in the chain.
			 */
			sb++;
			ste_ctx->set_next_lu_type(ste_arr, sb->lu_type);
			ste_ctx->set_byte_mask(ste_arr, sb->byte_mask);
		}
		ste_arr += DR_STE_SIZE;
	}
	return 0;
}

static void dr_ste_copy_mask_misc(char *mask, struct dr_match_misc *spec, bool clear)
{
	spec->gre_c_present = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, gre_c_present, clear);
	spec->bth_a = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, bth_a, clear);
	spec->gre_k_present = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, gre_k_present, clear);
	spec->gre_s_present = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, gre_s_present, clear);
	spec->source_vhca_port = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, source_vhca_port, clear);
	spec->source_sqn = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, source_sqn, clear);

	spec->source_eswitch_owner_vhca_id =
		DEVX_GET(dr_match_set_misc, mask, source_eswitch_owner_vhca_id);
	spec->source_port = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, source_port, clear);

	spec->outer_second_prio = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, outer_second_prio, clear);
	spec->outer_second_cfi = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, outer_second_cfi, clear);
	spec->outer_second_vid = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, outer_second_vid, clear);
	spec->inner_second_prio = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, inner_second_prio, clear);
	spec->inner_second_cfi = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, inner_second_cfi, clear);
	spec->inner_second_vid = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, inner_second_vid, clear);

	spec->outer_second_cvlan_tag =
		DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, outer_second_cvlan_tag, clear);
	spec->inner_second_cvlan_tag =
		DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, inner_second_cvlan_tag, clear);
	spec->outer_second_svlan_tag =
		DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, outer_second_svlan_tag, clear);
	spec->inner_second_svlan_tag =
		DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, inner_second_svlan_tag, clear);
	spec->outer_emd_tag = DEVX_GET(dr_match_set_misc, mask, outer_emd_tag);
	spec->reserved_at_65 = DEVX_GET(dr_match_set_misc, mask, reserved_at_65);
	spec->gre_protocol = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, gre_protocol, clear);

	spec->gre_key_h = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, gre_key_h, clear);
	spec->gre_key_l = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, gre_key_l, clear);

	spec->vxlan_vni = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, vxlan_vni, clear);
	spec->bth_opcode = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, bth_opcode, clear);

	spec->geneve_vni = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, geneve_vni, clear);
	spec->reserved_at_e4 = DEVX_GET(dr_match_set_misc, mask, reserved_at_e4);
	spec->geneve_oam = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, geneve_oam, clear);
	spec->reserved_at_ec = DEVX_GET(dr_match_set_misc, mask, reserved_at_ec);
	spec->geneve_tlv_option_0_exist =
		DEVX_GET(dr_match_set_misc, mask, geneve_tlv_option_0_exist);

	spec->outer_ipv6_flow_label =
		DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, outer_ipv6_flow_label, clear);

	spec->reserved_at_100 = DEVX_GET(dr_match_set_misc, mask, reserved_at_100);
	spec->inner_ipv6_flow_label =
		DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, inner_ipv6_flow_label, clear);

	spec->reserved_at_120 = DEVX_GET(dr_match_set_misc, mask, reserved_at_120);
	spec->geneve_opt_len = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, geneve_opt_len, clear);
	spec->geneve_protocol_type =
		DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, geneve_protocol_type, clear);

	spec->reserved_at_140 = DEVX_GET(dr_match_set_misc, mask, reserved_at_140);
	spec->bth_dst_qp = DR_DEVX_GET_CLEAR(dr_match_set_misc, mask, bth_dst_qp, clear);

	spec->inner_esp_spi = DEVX_GET(dr_match_set_misc, mask, inner_esp_spi);
	spec->outer_esp_spi = DEVX_GET(dr_match_set_misc, mask, outer_esp_spi);

	spec->reserved_at_1a0 = DEVX_GET(dr_match_set_misc, mask, reserved_at_1a0);
	spec->reserved_at_1c0 = DEVX_GET(dr_match_set_misc, mask, reserved_at_1c0);
	spec->reserved_at_1e0 = DEVX_GET(dr_match_set_misc, mask, reserved_at_1e0);
}

static void dr_ste_copy_mask_spec(char *mask, struct dr_match_spec *spec, bool clear)
{
	spec->smac_47_16 = DR_DEVX_GET_CLEAR(dr_match_spec, mask, smac_47_16, clear);

	spec->smac_15_0 = DR_DEVX_GET_CLEAR(dr_match_spec, mask, smac_15_0, clear);
	spec->ethertype = DR_DEVX_GET_CLEAR(dr_match_spec, mask, ethertype, clear);

	spec->dmac_47_16 = DR_DEVX_GET_CLEAR(dr_match_spec, mask, dmac_47_16, clear);

	spec->dmac_15_0 = DR_DEVX_GET_CLEAR(dr_match_spec, mask, dmac_15_0, clear);
	spec->first_prio = DR_DEVX_GET_CLEAR(dr_match_spec, mask, first_prio, clear);
	spec->first_cfi = DR_DEVX_GET_CLEAR(dr_match_spec, mask, first_cfi, clear);
	spec->first_vid = DR_DEVX_GET_CLEAR(dr_match_spec, mask, first_vid, clear);

	spec->ip_protocol = DR_DEVX_GET_CLEAR(dr_match_spec, mask, ip_protocol, clear);
	spec->ip_dscp = DR_DEVX_GET_CLEAR(dr_match_spec, mask, ip_dscp, clear);
	spec->ip_ecn = DR_DEVX_GET_CLEAR(dr_match_spec, mask, ip_ecn, clear);
	spec->cvlan_tag = DR_DEVX_GET_CLEAR(dr_match_spec, mask, cvlan_tag, clear);
	spec->svlan_tag = DR_DEVX_GET_CLEAR(dr_match_spec, mask, svlan_tag, clear);
	spec->frag = DR_DEVX_GET_CLEAR(dr_match_spec, mask, frag, clear);
	spec->ip_version = DR_DEVX_GET_CLEAR(dr_match_spec, mask, ip_version, clear);
	spec->tcp_flags = DR_DEVX_GET_CLEAR(dr_match_spec, mask, tcp_flags, clear);
	spec->tcp_sport = DR_DEVX_GET_CLEAR(dr_match_spec, mask, tcp_sport, clear);
	spec->tcp_dport = DR_DEVX_GET_CLEAR(dr_match_spec, mask, tcp_dport, clear);

	spec->reserved_at_c0 = DEVX_GET(dr_match_spec, mask, reserved_at_c0);
	spec->ipv4_ihl = DR_DEVX_GET_CLEAR(dr_match_spec, mask, ipv4_ihl, clear);
	spec->l3_ok = DR_DEVX_GET_CLEAR(dr_match_spec, mask, l3_ok, clear);
	spec->l4_ok = DR_DEVX_GET_CLEAR(dr_match_spec, mask, l4_ok, clear);
	spec->ipv4_checksum_ok = DR_DEVX_GET_CLEAR(dr_match_spec, mask, ipv4_checksum_ok, clear);
	spec->l4_checksum_ok = DR_DEVX_GET_CLEAR(dr_match_spec, mask, l4_checksum_ok, clear);
	spec->ip_ttl_hoplimit = DR_DEVX_GET_CLEAR(dr_match_spec, mask, ip_ttl_hoplimit, clear);

	spec->udp_sport = DR_DEVX_GET_CLEAR(dr_match_spec, mask, udp_sport, clear);
	spec->udp_dport = DR_DEVX_GET_CLEAR(dr_match_spec, mask, udp_dport, clear);

	spec->src_ip_127_96 = DR_DEVX_GET_CLEAR(dr_match_spec, mask, src_ip_127_96, clear);

	spec->src_ip_95_64 = DR_DEVX_GET_CLEAR(dr_match_spec, mask, src_ip_95_64, clear);

	spec->src_ip_63_32 = DR_DEVX_GET_CLEAR(dr_match_spec, mask, src_ip_63_32, clear);

	spec->src_ip_31_0 = DR_DEVX_GET_CLEAR(dr_match_spec, mask, src_ip_31_0, clear);

	spec->dst_ip_127_96 = DR_DEVX_GET_CLEAR(dr_match_spec, mask, dst_ip_127_96, clear);

	spec->dst_ip_95_64 = DR_DEVX_GET_CLEAR(dr_match_spec, mask, dst_ip_95_64, clear);

	spec->dst_ip_63_32 = DR_DEVX_GET_CLEAR(dr_match_spec, mask, dst_ip_63_32, clear);

	spec->dst_ip_31_0 = DR_DEVX_GET_CLEAR(dr_match_spec, mask, dst_ip_31_0, clear);
}

static void dr_ste_copy_mask_misc2(char *mask, struct dr_match_misc2 *spec, bool clear)
{
	spec->outer_first_mpls_label =
		DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, outer_first_mpls_label, clear);
	spec->outer_first_mpls_exp =
		DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, outer_first_mpls_exp, clear);
	spec->outer_first_mpls_s_bos =
		DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, outer_first_mpls_s_bos, clear);
	spec->outer_first_mpls_ttl =
		DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, outer_first_mpls_ttl, clear);
	spec->inner_first_mpls_label =
		DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, inner_first_mpls_label, clear);
	spec->inner_first_mpls_exp =
		DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, inner_first_mpls_exp, clear);
	spec->inner_first_mpls_s_bos =
		DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, inner_first_mpls_s_bos, clear);
	spec->inner_first_mpls_ttl =
		DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, inner_first_mpls_ttl, clear);
	spec->outer_first_mpls_over_gre_label =
		DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, outer_first_mpls_over_gre_label, clear);
	spec->outer_first_mpls_over_gre_exp =
		DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, outer_first_mpls_over_gre_exp, clear);
	spec->outer_first_mpls_over_gre_s_bos =
		DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, outer_first_mpls_over_gre_s_bos, clear);
	spec->outer_first_mpls_over_gre_ttl =
		DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, outer_first_mpls_over_gre_ttl, clear);
	spec->outer_first_mpls_over_udp_label =
		DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, outer_first_mpls_over_udp_label, clear);
	spec->outer_first_mpls_over_udp_exp =
		DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, outer_first_mpls_over_udp_exp, clear);
	spec->outer_first_mpls_over_udp_s_bos =
		DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, outer_first_mpls_over_udp_s_bos, clear);
	spec->outer_first_mpls_over_udp_ttl =
		DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, outer_first_mpls_over_udp_ttl, clear);
	spec->metadata_reg_c_7 = DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, metadata_reg_c_7, clear);
	spec->metadata_reg_c_6 = DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, metadata_reg_c_6, clear);
	spec->metadata_reg_c_5 = DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, metadata_reg_c_5, clear);
	spec->metadata_reg_c_4 = DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, metadata_reg_c_4, clear);
	spec->metadata_reg_c_3 = DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, metadata_reg_c_3, clear);
	spec->metadata_reg_c_2 = DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, metadata_reg_c_2, clear);
	spec->metadata_reg_c_1 = DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, metadata_reg_c_1, clear);
	spec->metadata_reg_c_0 = DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, metadata_reg_c_0, clear);
	spec->metadata_reg_a = DR_DEVX_GET_CLEAR(dr_match_set_misc2, mask, metadata_reg_a, clear);
	spec->reserved_at_1a0 = DEVX_GET(dr_match_set_misc2, mask, reserved_at_1a0);
	spec->reserved_at_1c0 = DEVX_GET(dr_match_set_misc2, mask, reserved_at_1c0);
	spec->reserved_at_1e0 = DEVX_GET(dr_match_set_misc2, mask, reserved_at_1e0);
}

static void dr_ste_copy_mask_misc3(char *mask, struct dr_match_misc3 *spec, bool clear)
{
	spec->inner_tcp_seq_num = DR_DEVX_GET_CLEAR(dr_match_set_misc3, mask, inner_tcp_seq_num, clear);
	spec->outer_tcp_seq_num = DR_DEVX_GET_CLEAR(dr_match_set_misc3, mask, outer_tcp_seq_num, clear);
	spec->inner_tcp_ack_num = DR_DEVX_GET_CLEAR(dr_match_set_misc3, mask, inner_tcp_ack_num, clear);
	spec->outer_tcp_ack_num = DR_DEVX_GET_CLEAR(dr_match_set_misc3, mask, outer_tcp_ack_num, clear);

	spec->reserved_at_80 = DEVX_GET(dr_match_set_misc3, mask, reserved_at_80);
	spec->outer_vxlan_gpe_vni =
		DR_DEVX_GET_CLEAR(dr_match_set_misc3, mask, outer_vxlan_gpe_vni, clear);
	spec->outer_vxlan_gpe_next_protocol =
		DR_DEVX_GET_CLEAR(dr_match_set_misc3, mask, outer_vxlan_gpe_next_protocol, clear);
	spec->outer_vxlan_gpe_flags =
		DR_DEVX_GET_CLEAR(dr_match_set_misc3, mask, outer_vxlan_gpe_flags, clear);
	spec->reserved_at_b0 = DEVX_GET(dr_match_set_misc3, mask, reserved_at_b0);

	spec->icmpv4_header_data = DR_DEVX_GET_CLEAR(dr_match_set_misc3, mask, icmp_header_data, clear);
	spec->icmpv6_header_data =
		DR_DEVX_GET_CLEAR(dr_match_set_misc3, mask, icmpv6_header_data, clear);
	spec->icmpv4_type = DR_DEVX_GET_CLEAR(dr_match_set_misc3, mask, icmp_type, clear);
	spec->icmpv4_code = DR_DEVX_GET_CLEAR(dr_match_set_misc3, mask, icmp_code, clear);
	spec->icmpv6_type = DR_DEVX_GET_CLEAR(dr_match_set_misc3, mask, icmpv6_type, clear);
	spec->icmpv6_code = DR_DEVX_GET_CLEAR(dr_match_set_misc3, mask, icmpv6_code, clear);
	spec->geneve_tlv_option_0_data =
		DR_DEVX_GET_CLEAR(dr_match_set_misc3, mask, geneve_tlv_option_0_data, clear);
	spec->gtpu_teid = DR_DEVX_GET_CLEAR(dr_match_set_misc3, mask, gtpu_teid, clear);
	spec->gtpu_msg_type = DR_DEVX_GET_CLEAR(dr_match_set_misc3, mask, gtpu_msg_type, clear);
	spec->gtpu_msg_flags = DR_DEVX_GET_CLEAR(dr_match_set_misc3, mask, gtpu_msg_flags, clear);
	spec->reserved_at_170 = DEVX_GET(dr_match_set_misc3, mask, reserved_at_170);
	spec->gtpu_dw_2 = DR_DEVX_GET_CLEAR(dr_match_set_misc3, mask, gtpu_dw_2, clear);
	spec->gtpu_first_ext_dw_0 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc3, mask, gtpu_first_ext_dw_0, clear);
	spec->gtpu_dw_0 = DR_DEVX_GET_CLEAR(dr_match_set_misc3, mask, gtpu_dw_0, clear);
	spec->reserved_at_1e0 = DEVX_GET(dr_match_set_misc3, mask, reserved_at_1e0);
}

static void dr_ste_copy_mask_misc4(char *mask, struct dr_match_misc4 *spec, bool clear)
{
	spec->prog_sample_field_id_0 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc4, mask, prog_sample_field_id_0, clear);
	spec->prog_sample_field_value_0 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc4, mask, prog_sample_field_value_0, clear);
	spec->prog_sample_field_id_1 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc4, mask, prog_sample_field_id_1, clear);
	spec->prog_sample_field_value_1 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc4, mask, prog_sample_field_value_1, clear);
	spec->prog_sample_field_id_2 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc4, mask, prog_sample_field_id_2, clear);
	spec->prog_sample_field_value_2 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc4, mask, prog_sample_field_value_2, clear);
	spec->prog_sample_field_id_3 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc4, mask, prog_sample_field_id_3, clear);
	spec->prog_sample_field_value_3 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc4, mask, prog_sample_field_value_3, clear);
	spec->prog_sample_field_id_4 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc4, mask, prog_sample_field_id_4, clear);
	spec->prog_sample_field_value_4 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc4, mask, prog_sample_field_value_4, clear);
	spec->prog_sample_field_id_5 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc4, mask, prog_sample_field_id_5, clear);
	spec->prog_sample_field_value_5 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc4, mask, prog_sample_field_value_5, clear);
	spec->prog_sample_field_id_6 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc4, mask, prog_sample_field_id_6, clear);
	spec->prog_sample_field_value_6 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc4, mask, prog_sample_field_value_6, clear);
	spec->prog_sample_field_id_7 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc4, mask, prog_sample_field_id_7, clear);
	spec->prog_sample_field_value_7 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc4, mask, prog_sample_field_value_7, clear);
}

static void dr_ste_copy_mask_misc5(char *mask, struct dr_match_misc5 *spec, bool clear)
{
	spec->macsec_tag_0 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc5, mask, macsec_tag_0, clear);
	spec->macsec_tag_1 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc5, mask, macsec_tag_1, clear);
	spec->macsec_tag_2 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc5, mask, macsec_tag_2, clear);
	spec->macsec_tag_3 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc5, mask, macsec_tag_3, clear);
	spec->tunnel_header_0 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc5, mask, tunnel_header_0, clear);
	spec->tunnel_header_1 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc5, mask, tunnel_header_1, clear);
	spec->tunnel_header_2 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc5, mask, tunnel_header_2, clear);
	spec->tunnel_header_3 =
		DR_DEVX_GET_CLEAR(dr_match_set_misc5, mask, tunnel_header_3, clear);
	spec->reserved_at_100 =
		DEVX_GET(dr_match_set_misc5, mask, reserved_at_100);
	spec->reserved_at_120 =
		DEVX_GET(dr_match_set_misc5, mask, reserved_at_120);
	spec->reserved_at_140 =
		DEVX_GET(dr_match_set_misc5, mask, reserved_at_140);
	spec->reserved_at_160 =
		DEVX_GET(dr_match_set_misc5, mask, reserved_at_160);
	spec->reserved_at_180 =
		DEVX_GET(dr_match_set_misc5, mask, reserved_at_180);
	spec->reserved_at_1a0 =
		DEVX_GET(dr_match_set_misc5, mask, reserved_at_1a0);
	spec->reserved_at_1c0 =
		DEVX_GET(dr_match_set_misc5, mask, reserved_at_1c0);
	spec->reserved_at_1e0 =
		DEVX_GET(dr_match_set_misc5, mask, reserved_at_1e0);
}

void dr_ste_copy_param(uint8_t match_criteria,
		       struct dr_match_param *set_param,
		       uint64_t *mask_buf, size_t mask_sz, bool clear)
{
	uint8_t *data = (uint8_t *)mask_buf;
	char tail_param[DEVX_ST_SZ_BYTES(dr_match_param)] = {};
	size_t param_location;
	void *buff;

	if (match_criteria & DR_MATCHER_CRITERIA_OUTER) {
		if (mask_sz < DEVX_ST_SZ_BYTES(dr_match_spec)) {
			memcpy(tail_param, data, mask_sz);
			buff = tail_param;
		} else {
			buff = mask_buf;
		}
		dr_ste_copy_mask_spec(buff, &set_param->outer, clear);
	}
	param_location = DEVX_ST_SZ_BYTES(dr_match_spec);

	if (match_criteria & DR_MATCHER_CRITERIA_MISC) {
		if (mask_sz < param_location +
		    DEVX_ST_SZ_BYTES(dr_match_set_misc)) {
			memcpy(tail_param, data + param_location,
			       mask_sz - param_location);
			buff = tail_param;
		} else {
			buff = data + param_location;
		}
		dr_ste_copy_mask_misc(buff, &set_param->misc, clear);
	}
	param_location += DEVX_ST_SZ_BYTES(dr_match_set_misc);

	if (match_criteria & DR_MATCHER_CRITERIA_INNER) {
		if (mask_sz < param_location +
		    DEVX_ST_SZ_BYTES(dr_match_spec)) {
			memcpy(tail_param, data + param_location,
			       mask_sz - param_location);
			buff = tail_param;
		} else {
			buff = data + param_location;
		}
		dr_ste_copy_mask_spec(buff, &set_param->inner, clear);
	}
	param_location += DEVX_ST_SZ_BYTES(dr_match_spec);

	if (match_criteria & DR_MATCHER_CRITERIA_MISC2) {
		if (mask_sz < param_location +
		    DEVX_ST_SZ_BYTES(dr_match_set_misc2)) {
			memcpy(tail_param, data + param_location,
			       mask_sz - param_location);
			buff = tail_param;
		} else {
			buff = data + param_location;
		}
		dr_ste_copy_mask_misc2(buff, &set_param->misc2, clear);
	}
	param_location += DEVX_ST_SZ_BYTES(dr_match_set_misc2);

	if (match_criteria & DR_MATCHER_CRITERIA_MISC3) {
		if (mask_sz < param_location +
		    DEVX_ST_SZ_BYTES(dr_match_set_misc3)) {
			memcpy(tail_param, data + param_location,
			       mask_sz - param_location);
			buff = tail_param;
		} else {
			buff = data + param_location;
		}
		dr_ste_copy_mask_misc3(buff, &set_param->misc3, clear);
	}
	param_location += DEVX_ST_SZ_BYTES(dr_match_set_misc3);

	if (match_criteria & DR_MATCHER_CRITERIA_MISC4) {
		if (mask_sz < param_location +
		    DEVX_ST_SZ_BYTES(dr_match_set_misc4)) {
			memcpy(tail_param, data + param_location,
			       mask_sz - param_location);
			buff = tail_param;
		} else {
			buff = data + param_location;
		}
		dr_ste_copy_mask_misc4(buff, &set_param->misc4, clear);
	}
	param_location += DEVX_ST_SZ_BYTES(dr_match_set_misc4);

	if (match_criteria & DR_MATCHER_CRITERIA_MISC5) {
		if (mask_sz < param_location +
		    DEVX_ST_SZ_BYTES(dr_match_set_misc5)) {
			memcpy(tail_param, data + param_location,
			       mask_sz - param_location);
			buff = tail_param;
		} else {
			buff = data + param_location;
		}
		dr_ste_copy_mask_misc5(buff, &set_param->misc5, clear);
	}
}

void dr_ste_build_eth_l2_src_dst(struct dr_ste_ctx *ste_ctx,
				 struct dr_ste_build *sb,
				 struct dr_match_param *mask,
				 bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_eth_l2_src_dst_init(sb, mask);
}

void dr_ste_build_eth_l3_ipv6_dst(struct dr_ste_ctx *ste_ctx,
				  struct dr_ste_build *sb,
				  struct dr_match_param *mask,
				  bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_eth_l3_ipv6_dst_init(sb, mask);
}

void dr_ste_build_eth_l3_ipv6_src(struct dr_ste_ctx *ste_ctx,
				  struct dr_ste_build *sb,
				  struct dr_match_param *mask,
				  bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_eth_l3_ipv6_src_init(sb, mask);
}

void dr_ste_build_eth_l3_ipv4_5_tuple(struct dr_ste_ctx *ste_ctx,
				      struct dr_ste_build *sb,
				      struct dr_match_param *mask,
				      bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_eth_l3_ipv4_5_tuple_init(sb, mask);
}

void dr_ste_build_eth_l2_src(struct dr_ste_ctx *ste_ctx,
			     struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_eth_l2_src_init(sb, mask);
}

void dr_ste_build_eth_l2_dst(struct dr_ste_ctx *ste_ctx,
			     struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_eth_l2_dst_init(sb, mask);
}

void dr_ste_build_eth_l2_tnl(struct dr_ste_ctx *ste_ctx,
			     struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_eth_l2_tnl_init(sb, mask);
}

void dr_ste_build_eth_l3_ipv4_misc(struct dr_ste_ctx *ste_ctx,
				   struct dr_ste_build *sb,
				   struct dr_match_param *mask,
				   bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_eth_l3_ipv4_misc_init(sb, mask);
}

void dr_ste_build_eth_ipv6_l3_l4(struct dr_ste_ctx *ste_ctx,
				 struct dr_ste_build *sb,
				 struct dr_match_param *mask,
				 bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_eth_ipv6_l3_l4_init(sb, mask);
}

static int dr_ste_build_empty_always_hit_tag(struct dr_match_param *value,
					     struct dr_ste_build *sb,
					     uint8_t *tag)
{
	return 0;
}

void dr_ste_build_empty_always_hit(struct dr_ste_build *sb, bool rx)
{
	sb->rx = rx;
	sb->lu_type = DR_STE_LU_TYPE_DONT_CARE;
	sb->byte_mask = 0;
	sb->ste_build_tag_func = &dr_ste_build_empty_always_hit_tag;
}

void dr_ste_build_mpls(struct dr_ste_ctx *ste_ctx,
		       struct dr_ste_build *sb,
		       struct dr_match_param *mask,
		       bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_mpls_init(sb, mask);
}

void dr_ste_build_tnl_gre(struct dr_ste_ctx *ste_ctx,
			  struct dr_ste_build *sb,
			  struct dr_match_param *mask,
			  bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_tnl_gre_init(sb, mask);
}

void dr_ste_build_tnl_mpls_over_gre(struct dr_ste_ctx *ste_ctx,
				    struct dr_ste_build *sb,
				    struct dr_match_param *mask,
				    struct dr_devx_caps *caps,
				    bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	sb->caps = caps;
	ste_ctx->build_tnl_mpls_over_gre_init(sb, mask);
}

void dr_ste_build_tnl_mpls_over_udp(struct dr_ste_ctx *ste_ctx,
				    struct dr_ste_build *sb,
				    struct dr_match_param *mask,
				    struct dr_devx_caps *caps,
				    bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	sb->caps = caps;
	ste_ctx->build_tnl_mpls_over_udp_init(sb, mask);
}

void dr_ste_build_tnl_geneve_tlv_opt_exist(struct dr_ste_ctx *ste_ctx,
					   struct dr_ste_build *sb,
					   struct dr_match_param *mask,
					   struct dr_devx_caps *caps,
					   bool inner, bool rx)
{
	if (!ste_ctx->build_tnl_geneve_tlv_opt_exist_init)
		return;

	sb->rx = rx;
	sb->inner = inner;
	sb->caps = caps;
	ste_ctx->build_tnl_geneve_tlv_opt_exist_init(sb, mask);
}

void dr_ste_build_icmp(struct dr_ste_ctx *ste_ctx,
		       struct dr_ste_build *sb,
		       struct dr_match_param *mask,
		       struct dr_devx_caps *caps,
		       bool inner, bool rx)
{
	sb->rx = rx;
	sb->caps = caps;
	sb->inner = inner;
	ste_ctx->build_icmp_init(sb, mask);
}

void dr_ste_build_general_purpose(struct dr_ste_ctx *ste_ctx,
				  struct dr_ste_build *sb,
				  struct dr_match_param *mask,
				  bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_general_purpose_init(sb, mask);
}

void dr_ste_build_eth_l4_misc(struct dr_ste_ctx *ste_ctx,
			      struct dr_ste_build *sb,
			      struct dr_match_param *mask,
			      bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_eth_l4_misc_init(sb, mask);
}

void dr_ste_build_tnl_vxlan_gpe(struct dr_ste_ctx *ste_ctx,
				struct dr_ste_build *sb,
				struct dr_match_param *mask,
				bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_tnl_vxlan_gpe_init(sb, mask);
}

void dr_ste_build_tnl_geneve(struct dr_ste_ctx *ste_ctx,
			     struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_tnl_geneve_init(sb, mask);
}

void dr_ste_build_tnl_geneve_tlv_opt(struct dr_ste_ctx *ste_ctx,
				     struct dr_ste_build *sb,
				     struct dr_match_param *mask,
				     struct dr_devx_caps *caps,
				     bool inner, bool rx)
{
	sb->rx = rx;
	sb->caps = caps;
	sb->inner = inner;
	ste_ctx->build_tnl_geneve_tlv_opt_init(sb, mask);
}

void dr_ste_build_tnl_gtpu(struct dr_ste_ctx *ste_ctx,
			   struct dr_ste_build *sb,
			   struct dr_match_param *mask,
			   bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_tnl_gtpu_init(sb, mask);
}

void dr_ste_build_tnl_gtpu_flex_parser_0(struct dr_ste_ctx *ste_ctx,
					 struct dr_ste_build *sb,
					 struct dr_match_param *mask,
					 struct dr_devx_caps *caps,
					 bool inner, bool rx)
{
	sb->rx = rx;
	sb->caps = caps;
	sb->inner = inner;
	ste_ctx->build_tnl_gtpu_flex_parser_0(sb, mask);
}

void dr_ste_build_tnl_gtpu_flex_parser_1(struct dr_ste_ctx *ste_ctx,
					 struct dr_ste_build *sb,
					 struct dr_match_param *mask,
					 struct dr_devx_caps *caps,
					 bool inner, bool rx)
{
	sb->rx = rx;
	sb->caps = caps;
	sb->inner = inner;
	ste_ctx->build_tnl_gtpu_flex_parser_1(sb, mask);
}

void dr_ste_build_register_0(struct dr_ste_ctx *ste_ctx,
			     struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_register_0_init(sb, mask);
}

void dr_ste_build_register_1(struct dr_ste_ctx *ste_ctx,
			     struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_register_1_init(sb, mask);
}

void dr_ste_build_src_gvmi_qpn(struct dr_ste_ctx *ste_ctx,
			       struct dr_ste_build *sb,
			       struct dr_match_param *mask,
			       struct dr_devx_caps *caps,
			       bool inner, bool rx)
{
	sb->rx = rx;
	sb->caps = caps;
	sb->inner = inner;
	ste_ctx->build_src_gvmi_qpn_init(sb, mask);
}

void dr_ste_build_flex_parser_0(struct dr_ste_ctx *ste_ctx,
				struct dr_ste_build *sb,
				struct dr_match_param *mask,
				bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_flex_parser_0_init(sb, mask);
}

void dr_ste_build_flex_parser_1(struct dr_ste_ctx *ste_ctx,
				struct dr_ste_build *sb,
				struct dr_match_param *mask,
				bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_flex_parser_1_init(sb, mask);
}

void dr_ste_build_tunnel_header(struct dr_ste_ctx *ste_ctx,
				struct dr_ste_build *sb,
				struct dr_match_param *mask,
				struct dr_devx_caps *caps,
				bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	sb->caps = caps;

	ste_ctx->build_tunnel_header_init(sb, mask);
}

void dr_ste_build_ib_l4(struct dr_ste_ctx *ste_ctx,
			struct dr_ste_build *sb,
			struct dr_match_param *mask,
			bool inner, bool rx)
{
	if (!ste_ctx->build_ib_l4_init)
		return;

	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_ib_l4_init(sb, mask);
}

int dr_ste_build_def0(struct dr_ste_ctx *ste_ctx,
		      struct dr_ste_build *sb,
		      struct dr_match_param *mask,
		      struct dr_devx_caps *caps,
		      bool inner, bool rx)
{
	if (!ste_ctx->build_def0_init) {
		errno = ENOTSUP;
		return errno;
	}

	sb->rx = rx;
	sb->caps = caps;
	sb->inner = inner;
	sb->format_id = DR_MATCHER_DEFINER_0;
	ste_ctx->build_def0_init(sb, mask);
	return 0;
}

int dr_ste_build_def2(struct dr_ste_ctx *ste_ctx,
		      struct dr_ste_build *sb,
		      struct dr_match_param *mask,
		      struct dr_devx_caps *caps,
		      bool inner, bool rx)
{
	if (!ste_ctx->build_def2_init) {
		errno = ENOTSUP;
		return errno;
	}

	sb->rx = rx;
	sb->caps = caps;
	sb->inner = inner;
	sb->format_id = DR_MATCHER_DEFINER_2;
	ste_ctx->build_def2_init(sb, mask);
	return 0;
}

int dr_ste_build_def6(struct dr_ste_ctx *ste_ctx,
		      struct dr_ste_build *sb,
		      struct dr_match_param *mask,
		      bool inner, bool rx)
{
	if (!ste_ctx->build_def6_init) {
		errno = ENOTSUP;
		return errno;
	}

	sb->rx = rx;
	sb->inner = inner;
	sb->format_id = DR_MATCHER_DEFINER_6;
	ste_ctx->build_def6_init(sb, mask);
	return 0;
}

int dr_ste_build_def16(struct dr_ste_ctx *ste_ctx,
		       struct dr_ste_build *sb,
		       struct dr_match_param *mask,
		       struct dr_devx_caps *caps,
		       bool inner, bool rx)
{
	if (!ste_ctx->build_def16_init) {
		errno = ENOTSUP;
		return errno;
	}

	sb->rx = rx;
	sb->caps = caps;
	sb->inner = inner;
	sb->format_id = DR_MATCHER_DEFINER_16;
	ste_ctx->build_def16_init(sb, mask);
	return 0;
}

int dr_ste_build_def22(struct dr_ste_ctx *ste_ctx,
		       struct dr_ste_build *sb,
		       struct dr_match_param *mask,
		       bool inner, bool rx)
{
	if (!ste_ctx->build_def22_init) {
		errno = ENOTSUP;
		return errno;
	}

	sb->rx = rx;
	sb->inner = inner;
	sb->format_id = DR_MATCHER_DEFINER_22;
	ste_ctx->build_def22_init(sb, mask);
	return 0;
}

int dr_ste_build_def24(struct dr_ste_ctx *ste_ctx,
		       struct dr_ste_build *sb,
		       struct dr_match_param *mask,
		       bool inner, bool rx)
{
	if (!ste_ctx->build_def24_init) {
		errno = ENOTSUP;
		return errno;
	}

	sb->rx = rx;
	sb->inner = inner;
	sb->format_id = DR_MATCHER_DEFINER_24;
	ste_ctx->build_def24_init(sb, mask);
	return 0;
}

int dr_ste_build_def25(struct dr_ste_ctx *ste_ctx,
		       struct dr_ste_build *sb,
		       struct dr_match_param *mask,
		       bool inner, bool rx)
{
	if (!ste_ctx->build_def25_init) {
		errno = ENOTSUP;
		return errno;
	}

	sb->rx = rx;
	sb->inner = inner;
	sb->format_id = DR_MATCHER_DEFINER_25;
	ste_ctx->build_def25_init(sb, mask);
	return 0;
}

int dr_ste_build_def26(struct dr_ste_ctx *ste_ctx,
		       struct dr_ste_build *sb,
		       struct dr_match_param *mask,
		       bool inner, bool rx)
{
	if (!ste_ctx->build_def26_init) {
		errno = ENOTSUP;
		return errno;
	}

	sb->rx = rx;
	sb->inner = inner;
	sb->format_id = DR_MATCHER_DEFINER_26;
	ste_ctx->build_def26_init(sb, mask);
	return 0;
}

int dr_ste_build_def28(struct dr_ste_ctx *ste_ctx,
		       struct dr_ste_build *sb,
		       struct dr_match_param *mask,
		       bool inner, bool rx)
{
	if (!ste_ctx->build_def28_init) {
		errno = ENOTSUP;
		return errno;
	}

	sb->rx = rx;
	sb->inner = inner;
	sb->format_id = DR_MATCHER_DEFINER_28;
	ste_ctx->build_def28_init(sb, mask);
	return 0;
}

int dr_ste_build_def33(struct dr_ste_ctx *ste_ctx,
		       struct dr_ste_build *sb,
		       struct dr_match_param *mask,
		       bool inner, bool rx)
{
	if (!ste_ctx->build_def33_init) {
		errno = ENOTSUP;
		return errno;
	}

	sb->rx = rx;
	sb->inner = inner;
	sb->format_id = DR_MATCHER_DEFINER_33;
	ste_ctx->build_def33_init(sb, mask);
	return 0;
}

struct dr_ste_ctx *dr_ste_get_ctx(uint8_t version)
{
	if (version == MLX5_HW_CONNECTX_5)
		return dr_ste_get_ctx_v0();
	else if (version == MLX5_HW_CONNECTX_6DX)
		return dr_ste_get_ctx_v1();
	else if (version == MLX5_HW_CONNECTX_7)
		return dr_ste_get_ctx_v2();

	errno = EOPNOTSUPP;

	return NULL;
}

int mlx5dv_dr_aso_other_domain_link(struct mlx5dv_devx_obj *devx_obj,
				    struct mlx5dv_dr_domain *peer_dmn,
				    struct mlx5dv_dr_domain *dmn,
				    uint32_t flags,
				    uint8_t return_reg_c)
{
	struct dr_ste_ctx *ste_ctx = dmn->ste_ctx;

	if (devx_obj->type != MLX5_DEVX_ASO_CT)
		goto out;

	if (ste_ctx->aso_other_domain_link)
		return ste_ctx->aso_other_domain_link(devx_obj, peer_dmn,
						      dmn, flags,
						      return_reg_c);

out:
	errno = EOPNOTSUPP;
	return errno;
}

int mlx5dv_dr_aso_other_domain_unlink(struct mlx5dv_devx_obj *devx_obj,
				      struct mlx5dv_dr_domain *dmn)
{
	struct dr_ste_ctx *ste_ctx = dmn->ste_ctx;

	if (ste_ctx->aso_other_domain_unlink)
		return ste_ctx->aso_other_domain_unlink(devx_obj);

	errno = EOPNOTSUPP;
	return errno;
}
