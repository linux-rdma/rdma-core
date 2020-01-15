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

#include "dr_ste.h"

#define DR_STE_ENABLE_FLOW_TAG (1 << 31)

enum dr_ste_tunl_action {
	DR_STE_TUNL_ACTION_NONE		= 0,
	DR_STE_TUNL_ACTION_ENABLE	= 1,
	DR_STE_TUNL_ACTION_DECAP	= 2,
	DR_STE_TUNL_ACTION_L3_DECAP	= 3,
};

enum dr_ste_action_type {
	DR_STE_ACTION_TYPE_ENCAP_L3	= 3,
	DR_STE_ACTION_TYPE_ENCAP	= 4,
};

struct dr_hw_ste_format {
	uint8_t ctrl[DR_STE_SIZE_CTRL];
	uint8_t tag[DR_STE_SIZE_TAG];
	uint8_t mask[DR_STE_SIZE_MASK];
};

uint32_t dr_ste_calc_hash_index(uint8_t *hw_ste_p,
				struct dr_ste_htbl *htbl)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	uint8_t masked[DR_STE_SIZE_TAG] = {};
	uint32_t crc32, index;
	uint16_t bit;
	int i;

	/* Don't calculate CRC if the result is predicted */
	if (htbl->chunk->num_of_entries == 1 || htbl->byte_mask == 0)
		return 0;

	/* Mask tag using byte mask, bit per byte */
	bit = 1 << (DR_STE_SIZE_TAG - 1);
	for (i = 0; i < DR_STE_SIZE_TAG; i++) {
		if (htbl->byte_mask & bit)
			masked[i] = hw_ste->tag[i];

		bit = bit >> 1;
	}

	crc32 = dr_crc32_slice8_calc(masked, DR_STE_SIZE_TAG);
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

void dr_ste_set_bit_mask(uint8_t *hw_ste_p, uint8_t *bit_mask)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;

	memcpy(hw_ste->mask, bit_mask, DR_STE_SIZE_MASK);
}

static void dr_ste_rx_set_flow_tag(uint8_t *hw_ste_p, uint32_t flow_tag)
{
	DR_STE_SET(rx_steering_mult, hw_ste_p, qp_list_pointer,
		   DR_STE_ENABLE_FLOW_TAG | flow_tag);
}

static void dr_ste_set_counter_id(uint8_t *hw_ste_p, uint32_t ctr_id)
{
	/* This can be used for both rx_steering_mult and for sx_transmit */
	DR_STE_SET(rx_steering_mult, hw_ste_p, counter_trigger_15_0, ctr_id);
	DR_STE_SET(rx_steering_mult, hw_ste_p, counter_trigger_23_16, ctr_id >> 16);
}

static void dr_ste_set_tx_encap(void *hw_ste_p, uint32_t reformat_id, int size, bool encap_l3)
{
	DR_STE_SET(sx_transmit, hw_ste_p, action_type,
		   encap_l3 ? DR_STE_ACTION_TYPE_ENCAP_L3 : DR_STE_ACTION_TYPE_ENCAP);
	/* The hardware expects here size in words (2 byte) */
	DR_STE_SET(sx_transmit, hw_ste_p, action_description, size / 2);
	DR_STE_SET(sx_transmit, hw_ste_p, encap_pointer_vlan_data, reformat_id);
}

static void dr_ste_set_rx_decap(uint8_t *hw_ste_p)
{
	DR_STE_SET(rx_steering_mult, hw_ste_p, tunneling_action,
		   DR_STE_TUNL_ACTION_DECAP);
}

static void dr_ste_set_rx_decap_l3(uint8_t *hw_ste_p, bool vlan)
{
	DR_STE_SET(rx_steering_mult, hw_ste_p, tunneling_action,
		   DR_STE_TUNL_ACTION_L3_DECAP);
	DR_STE_SET(modify_packet, hw_ste_p, action_description, vlan ? 1 : 0);
}

static void dr_ste_set_entry_type(uint8_t *hw_ste_p, uint8_t entry_type)
{
	DR_STE_SET(general, hw_ste_p, entry_type, entry_type);
}

static uint8_t dr_ste_get_entry_type(uint8_t *hw_ste_p)
{
	return DR_STE_GET(general, hw_ste_p, entry_type);
}

static void dr_ste_set_rewrite_actions(uint8_t *hw_ste_p, uint16_t num_of_actions,
				       uint32_t re_write_index)
{
	DR_STE_SET(modify_packet, hw_ste_p, number_of_re_write_actions,
		   num_of_actions);
	DR_STE_SET(modify_packet, hw_ste_p, header_re_write_actions_pointer,
		   re_write_index);
}

static void dr_ste_init(uint8_t *hw_ste_p, uint16_t lu_type, uint8_t entry_type,
			uint16_t gvmi)
{
	DR_STE_SET(general, hw_ste_p, entry_type, entry_type);
	DR_STE_SET(general, hw_ste_p, entry_sub_type, lu_type);
	DR_STE_SET(general, hw_ste_p, next_lu_type, DR_STE_LU_TYPE_DONT_CARE);

	/* Set GVMI once, this is the same for RX/TX
	 * bits 63_48 of next table base / miss address encode the next GVMI
	 */
	DR_STE_SET(rx_steering_mult, hw_ste_p, gvmi, gvmi);
	DR_STE_SET(rx_steering_mult, hw_ste_p, next_table_base_63_48, gvmi);
	DR_STE_SET(rx_steering_mult, hw_ste_p, miss_address_63_48, gvmi);
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

void dr_ste_set_miss_addr(uint8_t *hw_ste_p, uint64_t miss_addr)
{
	uint64_t index = miss_addr >> 6;

	/* Miss address for TX and RX STEs located in the same offsets */
	DR_STE_SET(rx_steering_mult, hw_ste_p, miss_address_39_32, index >> 26);
	DR_STE_SET(rx_steering_mult, hw_ste_p, miss_address_31_6, index);
}

static uint64_t dr_ste_get_miss_addr(uint8_t *hw_ste)
{
	uint64_t index =
		(DR_STE_GET(rx_steering_mult, hw_ste, miss_address_31_6) |
		 DR_STE_GET(rx_steering_mult, hw_ste, miss_address_39_32) << 26);

	return index << 6;
}

static void dr_ste_always_miss_addr(struct dr_ste *ste, uint64_t miss_addr)
{
	uint8_t *hw_ste_p = ste->hw_ste;

	DR_STE_SET(rx_steering_mult, hw_ste_p, next_lu_type, DR_STE_LU_TYPE_DONT_CARE);
	dr_ste_set_miss_addr(hw_ste_p, miss_addr);
	dr_ste_set_always_miss((struct dr_hw_ste_format *)ste->hw_ste);
}

void dr_ste_set_hit_addr(uint8_t *hw_ste, uint64_t icm_addr, uint32_t ht_size)
{
	uint64_t index = (icm_addr >> 5) | ht_size;

	DR_STE_SET(general, hw_ste, next_table_base_39_32_size, index >> 27);
	DR_STE_SET(general, hw_ste, next_table_base_31_5_size, index);
}

uint64_t dr_ste_get_icm_addr(struct dr_ste *ste)
{
	uint32_t index = ste - ste->htbl->ste_arr;

	return ste->htbl->chunk->icm_addr + DR_STE_SIZE * index;
}

uint64_t dr_ste_get_mr_addr(struct dr_ste *ste)
{
	uint32_t index = ste - ste->htbl->ste_arr;

	return ste->htbl->chunk->mr_addr + DR_STE_SIZE * index;
}

struct list_head *dr_ste_get_miss_list(struct dr_ste *ste)
{
	uint32_t index = ste - ste->htbl->ste_arr;

	return &ste->htbl->miss_list[index];
}

static void dr_ste_always_hit_htbl(struct dr_ste *ste, struct dr_ste_htbl *next_htbl)
{
	struct dr_icm_chunk *chunk = next_htbl->chunk;
	uint8_t *hw_ste = ste->hw_ste;

	DR_STE_SET(general, hw_ste, byte_mask, next_htbl->byte_mask);
	DR_STE_SET(general, hw_ste, next_lu_type, next_htbl->lu_type);
	dr_ste_set_hit_addr(hw_ste, chunk->icm_addr, chunk->num_of_entries);

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
	memcpy(dst->hw_ste, src->hw_ste, DR_STE_SIZE_REDUCED);
	dst->next_htbl = src->next_htbl;
	if (dst->next_htbl)
		dst->next_htbl->pointing_ste = dst;

	atomic_init(&dst->refcount, atomic_load(&src->refcount));

	list_head_init(&dst->rule_list);
	list_append_list(&dst->rule_list, &src->rule_list);
}

/* Free ste which is the head and the only one in miss_list */
static void
dr_ste_remove_head_ste(struct dr_ste *ste,
		       struct dr_matcher_rx_tx *nic_matcher,
		       struct dr_ste_send_info *ste_info_head,
		       struct list_head *send_ste_list,
		       struct dr_ste_htbl *stats_tbl)
{
	uint8_t tmp_data_ste[DR_STE_SIZE] = {};
	struct dr_ste tmp_ste = {};
	uint64_t miss_addr;

	tmp_ste.hw_ste = tmp_data_ste;
	/*
	 * Use temp ste because dr_ste_always_miss_addr
	 * touches bit_mask area which doesn't exist at ste->hw_ste.
	 */
	memcpy(tmp_ste.hw_ste, ste->hw_ste, DR_STE_SIZE_REDUCED);
	miss_addr = nic_matcher->e_anchor->chunk->icm_addr;
	dr_ste_always_miss_addr(&tmp_ste, miss_addr);
	memcpy(ste->hw_ste, tmp_ste.hw_ste, DR_STE_SIZE_REDUCED);

	list_del_init(&ste->miss_list_node);

	/* Write full STE size in order to have "always_miss" */
	dr_send_fill_and_append_ste_send_info(ste, DR_STE_SIZE,
					      0, tmp_data_ste,
					      ste_info_head,
					      send_ste_list,
					      true /* Copy data */);

	stats_tbl->ctrl.num_of_valid_entries--;
}

/*
 * Free ste which is the head but NOT the only one in miss_list:
 * |_ste_| --> |_next_ste_| -->|__| -->|__| -->/0
 */
static void
dr_ste_replace_head_ste(struct dr_ste *ste, struct dr_ste *next_ste,
			struct dr_ste_send_info *ste_info_head,
			struct list_head *send_ste_list,
			struct dr_ste_htbl *stats_tbl)

{
	struct dr_ste_htbl *next_miss_htbl;

	next_miss_htbl = next_ste->htbl;

	/* Remove from the miss_list the next_ste before copy */
	list_del_init(&next_ste->miss_list_node);

	/* All rule-members that use next_ste should know about that */
	dr_rule_update_rule_member(next_ste, ste);

	/* Move data from next into ste */
	dr_ste_replace(ste, next_ste);

	/*
	 * Del the htbl that contains the next_ste.
	 * The origin htbl stay with the same number of entries.
	 */
	dr_htbl_put(next_miss_htbl);

	dr_send_fill_and_append_ste_send_info(ste, DR_STE_SIZE_REDUCED,
					      0, ste->hw_ste,
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
static void dr_ste_remove_middle_ste(struct dr_ste *ste,
				     struct dr_ste_send_info *ste_info,
				     struct list_head *send_ste_list,
				     struct dr_ste_htbl *stats_tbl)
{
	struct dr_ste *prev_ste;
	uint64_t miss_addr;

	prev_ste = list_prev(dr_ste_get_miss_list(ste), ste, miss_list_node);
	assert(prev_ste);

	miss_addr = dr_ste_get_miss_addr(ste->hw_ste);
	dr_ste_set_miss_addr(prev_ste->hw_ste, miss_addr);

	dr_send_fill_and_append_ste_send_info(prev_ste, DR_STE_SIZE_REDUCED, 0,
					      prev_ste->hw_ste, ste_info,
					      send_ste_list, true /* Copy data*/);

	list_del_init(&ste->miss_list_node);

	stats_tbl->ctrl.num_of_valid_entries--;
	stats_tbl->ctrl.num_of_collisions--;
}

void dr_ste_free(struct dr_ste *ste,
		 struct mlx5dv_dr_matcher *matcher,
		 struct dr_matcher_rx_tx *nic_matcher)
{
	struct dr_ste_send_info *cur_ste_info, *tmp_ste_info;
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	struct dr_ste_send_info ste_info_head;
	struct dr_ste *next_ste, *first_ste;
	LIST_HEAD(send_ste_list);
	bool put_on_origin_table = true;
	struct dr_ste_htbl *stats_tbl;

	first_ste = list_top(dr_ste_get_miss_list(ste), struct dr_ste, miss_list_node);
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
			dr_ste_remove_head_ste(ste, nic_matcher,
					       &ste_info_head,
					       &send_ste_list,
					       stats_tbl);
		} else {
			/* First but not only entry in the list */
			dr_ste_replace_head_ste(ste, next_ste, &ste_info_head,
						&send_ste_list, stats_tbl);
			put_on_origin_table = false;
		}
	} else { /* Ste in the middle of the list */
		dr_ste_remove_middle_ste(ste, &ste_info_head, &send_ste_list, stats_tbl);
	}

	/* Update HW */
	list_for_each_safe(&send_ste_list, cur_ste_info, tmp_ste_info, send_list) {
		list_del(&cur_ste_info->send_list);
		dr_send_postsend_ste(dmn, cur_ste_info->ste,
				     cur_ste_info->data, cur_ste_info->size,
				     cur_ste_info->offset);
	}

	if (put_on_origin_table)
		dr_htbl_put(ste->htbl);
}

bool dr_ste_equal_tag(void *src, void *dst)
{
	struct dr_hw_ste_format *s_hw_ste = (struct dr_hw_ste_format *)src;
	struct dr_hw_ste_format *d_hw_ste = (struct dr_hw_ste_format *)dst;

	return !memcmp(s_hw_ste->tag, d_hw_ste->tag, DR_STE_SIZE_TAG);
}

void dr_ste_set_hit_addr_by_next_htbl(uint8_t *hw_ste,
				      struct dr_ste_htbl *next_htbl)
{
	struct dr_icm_chunk *chunk = next_htbl->chunk;

	dr_ste_set_hit_addr(hw_ste, chunk->icm_addr, chunk->num_of_entries);
}

/* Init one ste as a pattern for ste data array */
void dr_ste_set_formated_ste(uint16_t gvmi,
			     struct dr_domain_rx_tx *nic_dmn,
			     struct dr_ste_htbl *htbl,
			     uint8_t *formated_ste,
			     struct dr_htbl_connect_info *connect_info)
{
	struct dr_ste ste = {};

	dr_ste_init(formated_ste, htbl->lu_type, nic_dmn->ste_type, gvmi);
	ste.hw_ste = formated_ste;

	if (connect_info->type == CONNECT_HIT)
		dr_ste_always_hit_htbl(&ste, connect_info->hit_next_htbl);
	else
		dr_ste_always_miss_addr(&ste, connect_info->miss_icm_addr);
}

int dr_ste_htbl_init_and_postsend(struct mlx5dv_dr_domain *dmn,
				  struct dr_domain_rx_tx *nic_dmn,
				  struct dr_ste_htbl *htbl,
				  struct dr_htbl_connect_info *connect_info,
				  bool update_hw_ste)
{
	uint8_t formated_ste[DR_STE_SIZE] = {};

	dr_ste_set_formated_ste(dmn->info.caps.gvmi,
				nic_dmn,
				htbl,
				formated_ste,
				connect_info);

	return dr_send_postsend_formated_htbl(dmn, htbl, formated_ste, update_hw_ste);
}

int dr_ste_create_next_htbl(struct mlx5dv_dr_matcher *matcher,
			    struct dr_matcher_rx_tx *nic_matcher,
			    struct dr_ste *ste,
			    uint8_t *cur_hw_ste,
			    enum dr_icm_chunk_size log_table_size)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)cur_hw_ste;
	struct dr_domain_rx_tx *nic_dmn = nic_matcher->nic_tbl->nic_dmn;
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	struct dr_htbl_connect_info info;
	struct dr_ste_htbl *next_htbl;

	if (!dr_ste_is_last_in_rule(nic_matcher, ste->ste_chain_location)) {
		uint16_t next_lu_type;
		uint16_t byte_mask;

		next_lu_type = DR_STE_GET(general, hw_ste, next_lu_type);
		byte_mask = DR_STE_GET(general, hw_ste, byte_mask);

		next_htbl = dr_ste_htbl_alloc(dmn->ste_icm_pool,
					      log_table_size,
					      next_lu_type,
					      byte_mask);
		if (!next_htbl) {
			dr_dbg(dmn, "Failed allocating next hash table\n");
			return errno;
		}

		/* Write new table to HW */
		info.type = CONNECT_MISS;
		info.miss_icm_addr = nic_matcher->e_anchor->chunk->icm_addr;
		if (dr_ste_htbl_init_and_postsend(dmn, nic_dmn, next_htbl,
						  &info, false)) {
			dr_dbg(dmn, "Failed writing table to HW\n");
			goto free_table;
		}

		dr_ste_set_hit_addr_by_next_htbl(cur_hw_ste, next_htbl);
		ste->next_htbl = next_htbl;
		next_htbl->pointing_ste = ste;
	}

	return 0;

free_table:
	dr_ste_htbl_free(next_htbl);
	return ENOENT;
}

static void dr_ste_set_ctrl(struct dr_ste_htbl *htbl)
{
	struct dr_ste_htbl_ctrl *ctrl = &htbl->ctrl;
	int num_of_entries;

	htbl->ctrl.may_grow = true;

	if (htbl->chunk_size == DR_CHUNK_SIZE_MAX - 1 || !htbl->byte_mask)
		htbl->ctrl.may_grow = false;

	/* Threshold is 50%, one is added to table of size 1 */
	num_of_entries = dr_icm_pool_chunk_size_to_entries(htbl->chunk_size);
	ctrl->increase_threshold = (num_of_entries + 1) / 2;
}

struct dr_ste_htbl *dr_ste_htbl_alloc(struct dr_icm_pool *pool,
				      enum dr_icm_chunk_size chunk_size,
				      uint16_t lu_type, uint16_t byte_mask)
{
	struct dr_icm_chunk *chunk;
	struct dr_ste_htbl *htbl;
	int i;

	htbl = calloc(1, sizeof(struct dr_ste_htbl));
	if (!htbl) {
		errno = ENOMEM;
		return NULL;
	}

	chunk = dr_icm_alloc_chunk(pool, chunk_size);
	if (!chunk)
		goto out_free_htbl;

	htbl->chunk = chunk;
	htbl->lu_type = lu_type;
	htbl->byte_mask = byte_mask;
	htbl->ste_arr = chunk->ste_arr;
	htbl->hw_ste_arr = chunk->hw_ste_arr;
	htbl->miss_list = chunk->miss_list;
	atomic_init(&htbl->refcount, 0);

	for (i = 0; i < chunk->num_of_entries; i++) {
		struct dr_ste *ste = &htbl->ste_arr[i];

		ste->hw_ste = htbl->hw_ste_arr + i * DR_STE_SIZE_REDUCED;
		ste->htbl = htbl;
		atomic_init(&ste->refcount, 0);
		list_node_init(&ste->miss_list_node);
		list_head_init(&htbl->miss_list[i]);
		list_head_init(&ste->rule_list);
	}

	htbl->chunk_size = chunk_size;
	dr_ste_set_ctrl(htbl);
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

static void dr_ste_arr_init_next_ste(uint8_t **last_ste,
				     uint32_t *added_stes,
				     enum dr_ste_entry_type entry_type,
				     uint16_t gvmi)
{
	(*added_stes)++;
	*last_ste += DR_STE_SIZE;
	dr_ste_init(*last_ste, DR_STE_LU_TYPE_DONT_CARE, entry_type, gvmi);
}

void dr_ste_set_actions_tx(uint8_t *action_type_set,
			   uint8_t *last_ste,
			   struct dr_ste_actions_attr *attr,
			   uint32_t *added_stes)
{
	/* We want to make sure the modify header comes before L2
	 * encapsulation. The reason for that is that we support
	 * modify headers for outer headers only
	 */
	if (action_type_set[DR_ACTION_TYP_MODIFY_HDR]) {
		dr_ste_set_entry_type(last_ste, DR_STE_TYPE_MODIFY_PKT);
		dr_ste_set_rewrite_actions(last_ste,
					   attr->modify_actions,
					   attr->modify_index);
	}

	if (action_type_set[DR_ACTION_TYP_L2_TO_TNL_L2] ||
	    action_type_set[DR_ACTION_TYP_L2_TO_TNL_L3]) {
		/* Modify header and encapsulation require a different STEs.
		 * Since modify header STE format doesn't support encapsulation
		 * tunneling_action.
		 */
		if (action_type_set[DR_ACTION_TYP_MODIFY_HDR])
			dr_ste_arr_init_next_ste(&last_ste,
						 added_stes,
						 DR_STE_TYPE_TX,
						 attr->gvmi);

		dr_ste_set_tx_encap(last_ste,
				    attr->reformat_id,
				    attr->reformat_size,
				    action_type_set[DR_ACTION_TYP_L2_TO_TNL_L3]);
	}

	if (action_type_set[DR_ACTION_TYP_CTR])
		dr_ste_set_counter_id(last_ste, attr->ctr_id);

	dr_ste_set_hit_addr(last_ste, attr->final_icm_addr, 1);
}

void dr_ste_set_actions_rx(uint8_t *action_type_set,
			   uint8_t *last_ste,
			   struct dr_ste_actions_attr *attr,
			   uint32_t *added_stes)
{
	if (action_type_set[DR_ACTION_TYP_CTR])
		dr_ste_set_counter_id(last_ste, attr->ctr_id);

	if (action_type_set[DR_ACTION_TYP_TNL_L3_TO_L2]) {
		dr_ste_set_entry_type(last_ste, DR_STE_TYPE_MODIFY_PKT);
		dr_ste_set_rx_decap_l3(last_ste, attr->decap_with_vlan);
		dr_ste_set_rewrite_actions(last_ste,
					   attr->decap_actions,
					   attr->decap_index);
	}

	if (action_type_set[DR_ACTION_TYP_TNL_L2_TO_L2])
		dr_ste_set_rx_decap(last_ste);

	if (action_type_set[DR_ACTION_TYP_MODIFY_HDR]) {
		if (dr_ste_get_entry_type(last_ste) == DR_STE_TYPE_MODIFY_PKT)
			dr_ste_arr_init_next_ste(&last_ste,
						 added_stes,
						 DR_STE_TYPE_MODIFY_PKT,
						 attr->gvmi);
		else
			dr_ste_set_entry_type(last_ste, DR_STE_TYPE_MODIFY_PKT);

		dr_ste_set_rewrite_actions(last_ste,
					   attr->modify_actions,
					   attr->modify_index);
	}

	if (action_type_set[DR_ACTION_TYP_TAG]) {
		if (dr_ste_get_entry_type(last_ste) == DR_STE_TYPE_MODIFY_PKT)
			dr_ste_arr_init_next_ste(&last_ste,
						 added_stes,
						 DR_STE_TYPE_RX,
						 attr->gvmi);

		dr_ste_rx_set_flow_tag(last_ste, attr->flow_tag);
	}

	dr_ste_set_hit_addr(last_ste, attr->final_icm_addr, 1);
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
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	struct dr_ste_build *sb;
	int ret, i;

	ret = dr_ste_build_pre_check(dmn, matcher->match_criteria,
				     &matcher->mask, value);
	if (ret)
		return ret;

	sb = nic_matcher->ste_builder;
	for (i = 0; i < nic_matcher->num_of_builders; i++) {
		dr_ste_init(ste_arr,
			    sb->lu_type,
			    nic_dmn->ste_type,
			    dmn->info.caps.gvmi);

		dr_ste_set_bit_mask(ste_arr, sb->bit_mask);

		ret = sb->ste_build_tag_func(value, sb, dr_ste_get_tag(ste_arr));
		if (ret)
			return ret;

		/* Connect the STEs */
		if (i < (nic_matcher->num_of_builders - 1)) {
			/* Need the next builder for these fields,
			 * not relevant for the last ste in the chain.
			 */
			sb++;
			DR_STE_SET(general, ste_arr, next_lu_type, sb->lu_type);
			DR_STE_SET(general, ste_arr, byte_mask, sb->byte_mask);
		}
		ste_arr += DR_STE_SIZE;
	}
	return 0;
}

static void dr_ste_copy_mask_misc(char *mask, struct dr_match_misc *spec)
{
	spec->gre_c_present = DEVX_GET(dr_match_set_misc, mask, gre_c_present);
	spec->gre_k_present = DEVX_GET(dr_match_set_misc, mask, gre_k_present);
	spec->gre_s_present = DEVX_GET(dr_match_set_misc, mask, gre_s_present);
	spec->source_vhca_port = DEVX_GET(dr_match_set_misc, mask, source_vhca_port);
	spec->source_sqn = DEVX_GET(dr_match_set_misc, mask, source_sqn);

	spec->source_port = DEVX_GET(dr_match_set_misc, mask, source_port);

	spec->outer_second_prio = DEVX_GET(dr_match_set_misc, mask, outer_second_prio);
	spec->outer_second_cfi = DEVX_GET(dr_match_set_misc, mask, outer_second_cfi);
	spec->outer_second_vid = DEVX_GET(dr_match_set_misc, mask, outer_second_vid);
	spec->inner_second_prio = DEVX_GET(dr_match_set_misc, mask, inner_second_prio);
	spec->inner_second_cfi = DEVX_GET(dr_match_set_misc, mask, inner_second_cfi);
	spec->inner_second_vid = DEVX_GET(dr_match_set_misc, mask, inner_second_vid);

	spec->outer_second_cvlan_tag =
		DEVX_GET(dr_match_set_misc, mask, outer_second_cvlan_tag);
	spec->inner_second_cvlan_tag =
		DEVX_GET(dr_match_set_misc, mask, inner_second_cvlan_tag);
	spec->outer_second_svlan_tag =
		DEVX_GET(dr_match_set_misc, mask, outer_second_svlan_tag);
	spec->inner_second_svlan_tag =
		DEVX_GET(dr_match_set_misc, mask, inner_second_svlan_tag);

	spec->gre_protocol = DEVX_GET(dr_match_set_misc, mask, gre_protocol);

	spec->gre_key_h = DEVX_GET(dr_match_set_misc, mask, gre_key_h);
	spec->gre_key_l = DEVX_GET(dr_match_set_misc, mask, gre_key_l);

	spec->vxlan_vni = DEVX_GET(dr_match_set_misc, mask, vxlan_vni);

	spec->geneve_vni = DEVX_GET(dr_match_set_misc, mask, geneve_vni);
	spec->geneve_oam = DEVX_GET(dr_match_set_misc, mask, geneve_oam);

	spec->outer_ipv6_flow_label =
		DEVX_GET(dr_match_set_misc, mask, outer_ipv6_flow_label);

	spec->inner_ipv6_flow_label =
		DEVX_GET(dr_match_set_misc, mask, inner_ipv6_flow_label);

	spec->geneve_opt_len = DEVX_GET(dr_match_set_misc, mask, geneve_opt_len);
	spec->geneve_protocol_type =
		DEVX_GET(dr_match_set_misc, mask, geneve_protocol_type);

	spec->bth_dst_qp = DEVX_GET(dr_match_set_misc, mask, bth_dst_qp);
}

static void dr_ste_copy_mask_spec(char *mask, struct dr_match_spec *spec)
{
	spec->smac_47_16 = DEVX_GET(dr_match_spec, mask, smac_47_16);

	spec->smac_15_0 = DEVX_GET(dr_match_spec, mask, smac_15_0);
	spec->ethertype = DEVX_GET(dr_match_spec, mask, ethertype);

	spec->dmac_47_16 = DEVX_GET(dr_match_spec, mask, dmac_47_16);

	spec->dmac_15_0 = DEVX_GET(dr_match_spec, mask, dmac_15_0);
	spec->first_prio = DEVX_GET(dr_match_spec, mask, first_prio);
	spec->first_cfi = DEVX_GET(dr_match_spec, mask, first_cfi);
	spec->first_vid = DEVX_GET(dr_match_spec, mask, first_vid);

	spec->ip_protocol = DEVX_GET(dr_match_spec, mask, ip_protocol);
	spec->ip_dscp = DEVX_GET(dr_match_spec, mask, ip_dscp);
	spec->ip_ecn = DEVX_GET(dr_match_spec, mask, ip_ecn);
	spec->cvlan_tag = DEVX_GET(dr_match_spec, mask, cvlan_tag);
	spec->svlan_tag = DEVX_GET(dr_match_spec, mask, svlan_tag);
	spec->frag = DEVX_GET(dr_match_spec, mask, frag);
	spec->ip_version = DEVX_GET(dr_match_spec, mask, ip_version);
	spec->tcp_flags = DEVX_GET(dr_match_spec, mask, tcp_flags);
	spec->tcp_sport = DEVX_GET(dr_match_spec, mask, tcp_sport);
	spec->tcp_dport = DEVX_GET(dr_match_spec, mask, tcp_dport);

	spec->ip_ttl_hoplimit = DEVX_GET(dr_match_spec, mask, ip_ttl_hoplimit);

	spec->udp_sport = DEVX_GET(dr_match_spec, mask, udp_sport);
	spec->udp_dport = DEVX_GET(dr_match_spec, mask, udp_dport);

	spec->src_ip_127_96 = DEVX_GET(dr_match_spec, mask, src_ip_127_96);

	spec->src_ip_95_64 = DEVX_GET(dr_match_spec, mask, src_ip_95_64);

	spec->src_ip_63_32 = DEVX_GET(dr_match_spec, mask, src_ip_63_32);

	spec->src_ip_31_0 = DEVX_GET(dr_match_spec, mask, src_ip_31_0);

	spec->dst_ip_127_96 = DEVX_GET(dr_match_spec, mask, dst_ip_127_96);

	spec->dst_ip_95_64 = DEVX_GET(dr_match_spec, mask, dst_ip_95_64);

	spec->dst_ip_63_32 = DEVX_GET(dr_match_spec, mask, dst_ip_63_32);

	spec->dst_ip_31_0 = DEVX_GET(dr_match_spec, mask, dst_ip_31_0);
}

static void dr_ste_copy_mask_misc2(char *mask, struct dr_match_misc2 *spec)
{
	spec->outer_first_mpls_label =
		DEVX_GET(dr_match_set_misc2, mask, outer_first_mpls_label);
	spec->outer_first_mpls_exp =
		DEVX_GET(dr_match_set_misc2, mask, outer_first_mpls_exp);
	spec->outer_first_mpls_s_bos =
		DEVX_GET(dr_match_set_misc2, mask, outer_first_mpls_s_bos);
	spec->outer_first_mpls_ttl =
		DEVX_GET(dr_match_set_misc2, mask, outer_first_mpls_ttl);
	spec->inner_first_mpls_label =
		DEVX_GET(dr_match_set_misc2, mask, inner_first_mpls_label);
	spec->inner_first_mpls_exp =
		DEVX_GET(dr_match_set_misc2, mask, inner_first_mpls_exp);
	spec->inner_first_mpls_s_bos =
		DEVX_GET(dr_match_set_misc2, mask, inner_first_mpls_s_bos);
	spec->inner_first_mpls_ttl =
		DEVX_GET(dr_match_set_misc2, mask, inner_first_mpls_ttl);
	spec->outer_first_mpls_over_gre_label =
		DEVX_GET(dr_match_set_misc2, mask, outer_first_mpls_over_gre_label);
	spec->outer_first_mpls_over_gre_exp =
		DEVX_GET(dr_match_set_misc2, mask, outer_first_mpls_over_gre_exp);
	spec->outer_first_mpls_over_gre_s_bos =
		DEVX_GET(dr_match_set_misc2, mask, outer_first_mpls_over_gre_s_bos);
	spec->outer_first_mpls_over_gre_ttl =
		DEVX_GET(dr_match_set_misc2, mask, outer_first_mpls_over_gre_ttl);
	spec->outer_first_mpls_over_udp_label =
		DEVX_GET(dr_match_set_misc2, mask, outer_first_mpls_over_udp_label);
	spec->outer_first_mpls_over_udp_exp =
		DEVX_GET(dr_match_set_misc2, mask, outer_first_mpls_over_udp_exp);
	spec->outer_first_mpls_over_udp_s_bos =
		DEVX_GET(dr_match_set_misc2, mask, outer_first_mpls_over_udp_s_bos);
	spec->outer_first_mpls_over_udp_ttl =
		DEVX_GET(dr_match_set_misc2, mask, outer_first_mpls_over_udp_ttl);
	spec->metadata_reg_c_7 = DEVX_GET(dr_match_set_misc2, mask, metadata_reg_c_7);
	spec->metadata_reg_c_6 = DEVX_GET(dr_match_set_misc2, mask, metadata_reg_c_6);
	spec->metadata_reg_c_5 = DEVX_GET(dr_match_set_misc2, mask, metadata_reg_c_5);
	spec->metadata_reg_c_4 = DEVX_GET(dr_match_set_misc2, mask, metadata_reg_c_4);
	spec->metadata_reg_c_3 = DEVX_GET(dr_match_set_misc2, mask, metadata_reg_c_3);
	spec->metadata_reg_c_2 = DEVX_GET(dr_match_set_misc2, mask, metadata_reg_c_2);
	spec->metadata_reg_c_1 = DEVX_GET(dr_match_set_misc2, mask, metadata_reg_c_1);
	spec->metadata_reg_c_0 = DEVX_GET(dr_match_set_misc2, mask, metadata_reg_c_0);
	spec->metadata_reg_a = DEVX_GET(dr_match_set_misc2, mask, metadata_reg_a);
	spec->metadata_reg_b = DEVX_GET(dr_match_set_misc2, mask, metadata_reg_b);
}

static void dr_ste_copy_mask_misc3(char *mask, struct dr_match_misc3 *spec)
{
	spec->inner_tcp_seq_num = DEVX_GET(dr_match_set_misc3, mask, inner_tcp_seq_num);
	spec->outer_tcp_seq_num = DEVX_GET(dr_match_set_misc3, mask, outer_tcp_seq_num);
	spec->inner_tcp_ack_num = DEVX_GET(dr_match_set_misc3, mask, inner_tcp_ack_num);
	spec->outer_tcp_ack_num = DEVX_GET(dr_match_set_misc3, mask, outer_tcp_ack_num);
	spec->outer_vxlan_gpe_vni =
		DEVX_GET(dr_match_set_misc3, mask, outer_vxlan_gpe_vni);
	spec->outer_vxlan_gpe_next_protocol =
		DEVX_GET(dr_match_set_misc3, mask, outer_vxlan_gpe_next_protocol);
	spec->outer_vxlan_gpe_flags =
		DEVX_GET(dr_match_set_misc3, mask, outer_vxlan_gpe_flags);
	spec->icmpv4_header_data = DEVX_GET(dr_match_set_misc3, mask, icmp_header_data);
	spec->icmpv6_header_data =
		DEVX_GET(dr_match_set_misc3, mask, icmpv6_header_data);
	spec->icmpv4_type = DEVX_GET(dr_match_set_misc3, mask, icmp_type);
	spec->icmpv4_code = DEVX_GET(dr_match_set_misc3, mask, icmp_code);
	spec->icmpv6_type = DEVX_GET(dr_match_set_misc3, mask, icmpv6_type);
	spec->icmpv6_code = DEVX_GET(dr_match_set_misc3, mask, icmpv6_code);
	spec->gtpu_flags    = DEVX_GET(dr_match_set_misc3, mask, gtpu_flags);
	spec->gtpu_msg_type = DEVX_GET(dr_match_set_misc3, mask, gtpu_msg_type);
	spec->gtpu_teid     = DEVX_GET(dr_match_set_misc3, mask, gtpu_teid);
}

#define MAX_PARAM_SIZE 512

void dr_ste_copy_param(uint8_t match_criteria,
		       struct dr_match_param *set_param,
		       struct mlx5dv_flow_match_parameters *mask)
{
	char tail_param[MAX_PARAM_SIZE] = {};
	size_t param_location;
	uint8_t *data = (uint8_t *)mask->match_buf;
	void *buff;

	if (match_criteria & DR_MATCHER_CRITERIA_OUTER) {
		if (mask->match_sz < DEVX_ST_SZ_BYTES(dr_match_spec)) {
			memcpy(tail_param, data, mask->match_sz);
			buff = tail_param;
		} else {
			buff = mask->match_buf;
		}
		dr_ste_copy_mask_spec(buff, &set_param->outer);
	}
	param_location = DEVX_ST_SZ_BYTES(dr_match_spec);

	if (match_criteria & DR_MATCHER_CRITERIA_MISC) {
		if (mask->match_sz < param_location +
		    DEVX_ST_SZ_BYTES(dr_match_set_misc)) {
			memcpy(tail_param, data + param_location,
			       mask->match_sz - param_location);
			buff = tail_param;
		} else {
			buff = data + param_location;
		}
		dr_ste_copy_mask_misc(buff, &set_param->misc);
	}
	param_location += DEVX_ST_SZ_BYTES(dr_match_set_misc);

	if (match_criteria & DR_MATCHER_CRITERIA_INNER) {
		if (mask->match_sz < param_location +
		    DEVX_ST_SZ_BYTES(dr_match_spec)) {
			memcpy(tail_param, data + param_location,
			       mask->match_sz - param_location);
			buff = tail_param;
		} else {
			buff = data + param_location;
		}
		dr_ste_copy_mask_spec(buff, &set_param->inner);
	}
	param_location += DEVX_ST_SZ_BYTES(dr_match_spec);

	if (match_criteria & DR_MATCHER_CRITERIA_MISC2) {
		if (mask->match_sz < param_location +
		    DEVX_ST_SZ_BYTES(dr_match_set_misc2)) {
			memcpy(tail_param, data + param_location,
			       mask->match_sz - param_location);
			buff = tail_param;
		} else {
			buff = data + param_location;
		}
		dr_ste_copy_mask_misc2(buff, &set_param->misc2);
	}

	param_location += DEVX_ST_SZ_BYTES(dr_match_set_misc2);

	if (match_criteria & DR_MATCHER_CRITERIA_MISC3) {
		if (mask->match_sz < param_location +
		    DEVX_ST_SZ_BYTES(dr_match_set_misc3)) {
			memcpy(tail_param, data + param_location,
			       mask->match_sz - param_location);
			buff = tail_param;
		} else {
			buff = data + param_location;
		}
		dr_ste_copy_mask_misc3(buff, &set_param->misc3);
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

void dr_ste_build_tnl_mpls(struct dr_ste_ctx *ste_ctx,
			   struct dr_ste_build *sb,
			   struct dr_match_param *mask,
			   bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_tnl_mpls_init(sb, mask);
}

int dr_ste_build_icmp(struct dr_ste_ctx *ste_ctx,
		      struct dr_ste_build *sb,
		      struct dr_match_param *mask,
		      struct dr_devx_caps *caps,
		      bool inner, bool rx)
{
	sb->rx = rx;
	sb->caps = caps;
	sb->inner = inner;
	return ste_ctx->build_icmp_init(sb, mask);
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

void dr_ste_build_tnl_gtpu(struct dr_ste_ctx *ste_ctx,
			   struct dr_ste_build *sb,
			   struct dr_match_param *mask,
			   bool inner, bool rx)
{
	sb->rx = rx;
	sb->inner = inner;
	ste_ctx->build_tnl_gtpu_init(sb, mask);
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

struct dr_ste_ctx *dr_ste_get_ctx(uint8_t version)
{
	if (version == MLX5_HW_CONNECTX_5)
		return dr_ste_get_ctx_v0();

	errno = EOPNOTSUPP;

	return NULL;
}
