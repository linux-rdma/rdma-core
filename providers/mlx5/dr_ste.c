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
#include <string.h>
#include "mlx5dv_dr.h"

#define IPV4_ETHERTYPE    0x0800
#define IPV6_ETHERTYPE    0x86DD
#define STE_IPV4          0x1
#define STE_IPV6          0x2
#define STE_TCP           0x1
#define STE_UDP           0x2
#define STE_SPI           0x3
#define IP_VERSION_IPV4   0x4
#define IP_VERSION_IPV6   0x6
#define IP_PROTOCOL_UDP   0x11
#define IP_PROTOCOL_TCP   0x06
#define IP_PROTOCOL_IPSEC 0x33
#define TCP_PROTOCOL      0x6
#define UDP_PROTOCOL      0x11
#define IPSEC_PROTOCOL    0x33

#define DR_STE_ENABLE_FLOW_TAG (1 << 31)

/* Read from layout struct */
#define DR_STE_GET(typ, p, fld) DEVX_GET(ste_##typ, p, fld)

/* Write to layout a value */
#define DR_STE_SET(typ, p, fld, v) DEVX_SET(ste_##typ, p, fld, v)

#define DR_STE_SET_BOOL(typ, p, fld, v) DEVX_SET(ste_##typ, p, fld, !!(v))

/* Set to STE a specific value using DR_STE_SET */
#define DR_STE_SET_VAL(lookup_type, tag, t_fname, spec, s_fname, value) do { \
	if ((spec)->s_fname) { \
		DR_STE_SET(lookup_type, tag, t_fname, value); \
		(spec)->s_fname = 0; \
	} \
} while (0)

/* Set to STE spec->s_fname to tag->t_fname */
#define DR_STE_SET_TAG(lookup_type, tag, t_fname, spec, s_fname) \
	DR_STE_SET_VAL(lookup_type, tag, t_fname, spec, s_fname, (spec)->s_fname);

/* Set to STE -1 to bit_mask->bm_fname and set spec->s_fname as used */
#define DR_STE_SET_MASK(lookup_type, bit_mask, bm_fname, spec, s_fname) \
	DR_STE_SET_VAL(lookup_type, bit_mask, bm_fname, spec, s_fname, -1);

/* Set to STE spec->s_fname to bit_mask->bm_fname and set spec->s_fname as used */
#define DR_STE_SET_MASK_V(lookup_type, bit_mask, bm_fname, spec, s_fname) \
	DR_STE_SET_VAL(lookup_type, bit_mask, bm_fname, spec, s_fname, (spec)->s_fname);

#define DR_STE_SET_TCP_FLAGS(lookup_type, tag, spec) do { \
	DR_STE_SET_BOOL(lookup_type, tag, tcp_ns, (spec)->tcp_flags & (1 << 8)); \
	DR_STE_SET_BOOL(lookup_type, tag, tcp_cwr, (spec)->tcp_flags & (1 << 7)); \
	DR_STE_SET_BOOL(lookup_type, tag, tcp_ece, (spec)->tcp_flags & (1 << 6)); \
	DR_STE_SET_BOOL(lookup_type, tag, tcp_urg, (spec)->tcp_flags & (1 << 5)); \
	DR_STE_SET_BOOL(lookup_type, tag, tcp_ack, (spec)->tcp_flags & (1 << 4)); \
	DR_STE_SET_BOOL(lookup_type, tag, tcp_psh, (spec)->tcp_flags & (1 << 3)); \
	DR_STE_SET_BOOL(lookup_type, tag, tcp_rst, (spec)->tcp_flags & (1 << 2)); \
	DR_STE_SET_BOOL(lookup_type, tag, tcp_syn, (spec)->tcp_flags & (1 << 1)); \
	DR_STE_SET_BOOL(lookup_type, tag, tcp_fin, (spec)->tcp_flags & (1 << 0)); \
} while (0)

#define DR_STE_SET_MPLS_MASK(lookup_type, mask, in_out, bit_mask) do { \
	DR_STE_SET_MASK_V(lookup_type, mask, mpls0_label, mask, \
			  in_out##_first_mpls_label);\
	DR_STE_SET_MASK_V(lookup_type, mask, mpls0_s_bos, mask, \
			  in_out##_first_mpls_s_bos); \
	DR_STE_SET_MASK_V(lookup_type, mask, mpls0_exp, mask, \
			  in_out##_first_mpls_exp); \
	DR_STE_SET_MASK_V(lookup_type, mask, mpls0_ttl, mask, \
			  in_out##_first_mpls_ttl); \
} while (0)

#define DR_STE_SET_MPLS_TAG(lookup_type, mask, in_out, tag) do { \
	DR_STE_SET_TAG(lookup_type, tag, mpls0_label, mask, \
		       in_out##_first_mpls_label);\
	DR_STE_SET_TAG(lookup_type, tag, mpls0_s_bos, mask, \
		       in_out##_first_mpls_s_bos); \
	DR_STE_SET_TAG(lookup_type, tag, mpls0_exp, mask, \
		       in_out##_first_mpls_exp); \
	DR_STE_SET_TAG(lookup_type, tag, mpls0_ttl, mask, \
		       in_out##_first_mpls_ttl); \
} while (0)

#define DR_STE_IS_OUTER_MPLS_OVER_GRE_SET(_misc) (\
	(_misc)->outer_first_mpls_over_gre_label || \
	(_misc)->outer_first_mpls_over_gre_exp || \
	(_misc)->outer_first_mpls_over_gre_s_bos || \
	(_misc)->outer_first_mpls_over_gre_ttl)
#define DR_STE_IS_OUTER_MPLS_OVER_UDP_SET(_misc) (\
	(_misc)->outer_first_mpls_over_udp_label || \
	(_misc)->outer_first_mpls_over_udp_exp || \
	(_misc)->outer_first_mpls_over_udp_s_bos || \
	(_misc)->outer_first_mpls_over_udp_ttl)

#define DR_STE_CALC_LU_TYPE(lookup_type, rx, inner) \
	((inner) ? DR_STE_LU_TYPE_##lookup_type##_I : \
		   (rx) ? DR_STE_LU_TYPE_##lookup_type##_D : \
			  DR_STE_LU_TYPE_##lookup_type##_O)

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

static uint16_t dr_ste_conv_bit_to_byte_mask(uint8_t *bit_mask)
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

void dr_ste_set_bit_mask(uint8_t *hw_ste_p, uint8_t *bit_mask)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;

	memcpy(hw_ste->mask, bit_mask, DR_STE_SIZE_MASK);
}

void dr_ste_rx_set_flow_tag(uint8_t *hw_ste_p, uint32_t flow_tag)
{
	DR_STE_SET(rx_steering_mult, hw_ste_p, qp_list_pointer,
		   DR_STE_ENABLE_FLOW_TAG | flow_tag);
}

void dr_ste_set_counter_id(uint8_t *hw_ste_p, uint32_t ctr_id)
{
	/* This can be used for both rx_steering_mult and for sx_transmit */
	DR_STE_SET(rx_steering_mult, hw_ste_p, counter_trigger_15_0, ctr_id);
	DR_STE_SET(rx_steering_mult, hw_ste_p, counter_trigger_23_16, ctr_id >> 16);
}

void dr_ste_set_tx_encap(void *hw_ste_p, uint32_t reformat_id, int size, bool encap_l3)
{
	DR_STE_SET(sx_transmit, hw_ste_p, action_type,
		   encap_l3 ? DR_STE_ACTION_TYPE_ENCAP_L3 : DR_STE_ACTION_TYPE_ENCAP);
	/* The hardware expects here size in words (2 byte) */
	DR_STE_SET(sx_transmit, hw_ste_p, action_description, size / 2);
	DR_STE_SET(sx_transmit, hw_ste_p, encap_pointer_vlan_data, reformat_id);
}

void dr_ste_set_rx_decap(uint8_t *hw_ste_p)
{
	DR_STE_SET(rx_steering_mult, hw_ste_p, tunneling_action,
		   DR_STE_TUNL_ACTION_DECAP);
}

void dr_ste_set_rx_decap_l3(uint8_t *hw_ste_p, bool vlan)
{
	DR_STE_SET(rx_steering_mult, hw_ste_p, tunneling_action,
		   DR_STE_TUNL_ACTION_L3_DECAP);
	DR_STE_SET(modify_packet, hw_ste_p, action_description, vlan ? 1 : 0);
}

void dr_ste_set_entry_type(uint8_t *hw_ste_p, uint8_t entry_type)
{
	DR_STE_SET(general, hw_ste_p, entry_type, entry_type);
}

uint8_t dr_ste_get_entry_type(uint8_t *hw_ste_p)
{
	return DR_STE_GET(general, hw_ste_p, entry_type);
}

void dr_ste_set_rewrite_actions(uint8_t *hw_ste_p, uint16_t num_of_actions,
				uint32_t re_write_index)
{
	DR_STE_SET(modify_packet, hw_ste_p, number_of_re_write_actions,
		   num_of_actions);
	DR_STE_SET(modify_packet, hw_ste_p, header_re_write_actions_pointer,
		   re_write_index);
}

void dr_ste_init(uint8_t *hw_ste_p, uint8_t lu_type, uint8_t entry_type,
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

uint64_t dr_ste_get_miss_addr(uint8_t *hw_ste)
{
	uint64_t index =
		(DR_STE_GET(rx_steering_mult, hw_ste, miss_address_31_6) |
		 DR_STE_GET(rx_steering_mult, hw_ste, miss_address_39_32) << 26);

	return index << 6;
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

void dr_ste_always_hit_htbl(struct dr_ste *ste, struct dr_ste_htbl *next_htbl)
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

void dr_ste_set_miss_addr(uint8_t *hw_ste_p, uint64_t miss_addr)
{
	uint64_t index = miss_addr >> 6;

	/* Miss address for TX and RX STEs located in the same offsets */
	DR_STE_SET(rx_steering_mult, hw_ste_p, miss_address_39_32, index >> 26);
	DR_STE_SET(rx_steering_mult, hw_ste_p, miss_address_31_6, index);
}

void dr_ste_always_miss_addr(struct dr_ste *ste, uint64_t miss_addr)
{
	uint8_t *hw_ste = ste->hw_ste;

	DR_STE_SET(rx_steering_mult, hw_ste, next_lu_type, DR_STE_LU_TYPE_DONT_CARE);
	dr_ste_set_miss_addr(hw_ste, miss_addr);
	dr_ste_set_always_miss((struct dr_hw_ste_format *)ste->hw_ste);
}

/*
 * The assumption here is that we don't update the ste->hw_ste if it is not
 * used ste, so it will be all zero, checking the next_lu_type.
 */
bool dr_ste_is_not_valid_entry(uint8_t *p_hw_ste)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)p_hw_ste;

	if (DR_STE_GET(general, hw_ste, next_lu_type) ==
	    DR_STE_LU_TYPE_NOP)
		return true;

	return false;
}

bool dr_ste_not_used_ste(struct dr_ste *ste)
{
	return !atomic_load(&ste->refcount);
}

static inline uint16_t get_bits_per_mask(uint16_t byte_mask)
{
	uint16_t bits = 0;

	while (byte_mask) {
		byte_mask = byte_mask & (byte_mask - 1);
		bits++;
	}

	return bits;
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
		uint32_t bits_in_mask;
		uint8_t next_lu_type;
		uint16_t byte_mask;

		next_lu_type = DR_STE_GET(general, hw_ste, next_lu_type);
		byte_mask = DR_STE_GET(general, hw_ste, byte_mask);

		/* Don't allocate table more than required,
		 * the size of the table defined via the byte_mask, so no need
		 * to allocate more than that.
		 */
		bits_in_mask = get_bits_per_mask(byte_mask) * CHAR_BIT;
		log_table_size = min_t(uint32_t, log_table_size, bits_in_mask);

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

	if (htbl->chunk_size == DR_CHUNK_SIZE_MAX - 1)
		htbl->ctrl.may_grow = false;

	/* Threshold is 50%, one is added to table of size 1 */
	num_of_entries = dr_icm_pool_chunk_size_to_entries(htbl->chunk_size);
	ctrl->increase_threshold = (num_of_entries + 1) / 2;
}

struct dr_ste_htbl *dr_ste_htbl_alloc(struct dr_icm_pool *pool,
				      enum dr_icm_chunk_size chunk_size,
				      uint8_t lu_type, uint16_t byte_mask)
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

		ret = sb->ste_build_tag_func(value, sb, ste_arr);
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

static int dr_ste_build_eth_l2_src_des_bit_mask(struct dr_match_param *value,
						bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;

	DR_STE_SET_MASK_V(eth_l2_src_dst, bit_mask, dmac_47_16, mask, dmac_47_16);
	DR_STE_SET_MASK_V(eth_l2_src_dst, bit_mask, dmac_15_0, mask, dmac_15_0);

	if (mask->smac_47_16 || mask->smac_15_0) {
		DR_STE_SET(eth_l2_src_dst, bit_mask, smac_47_32,
			   mask->smac_47_16 >> 16);
		DR_STE_SET(eth_l2_src_dst, bit_mask, smac_31_0,
			   mask->smac_47_16 << 16 | mask->smac_15_0);
		mask->smac_47_16 = 0;
		mask->smac_15_0 = 0;
	}

	DR_STE_SET_MASK_V(eth_l2_src_dst, bit_mask, first_vlan_id, mask, first_vid);
	DR_STE_SET_MASK_V(eth_l2_src_dst, bit_mask, first_cfi, mask, first_cfi);
	DR_STE_SET_MASK_V(eth_l2_src_dst, bit_mask, first_priority, mask, first_prio);
	DR_STE_SET_MASK(eth_l2_src_dst, bit_mask, l3_type, mask, ip_version);

	if (mask->cvlan_tag) {
		DR_STE_SET(eth_l2_src_dst, bit_mask, first_vlan_qualifier, -1);
		mask->cvlan_tag = 0;
	} else if (mask->svlan_tag) {
		DR_STE_SET(eth_l2_src_dst, bit_mask, first_vlan_qualifier, -1);
		mask->svlan_tag = 0;
	}

	if (mask->cvlan_tag || mask->svlan_tag) {
		errno = EINVAL;
		return errno;
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
		if (mask->match_sz < sizeof(struct dr_match_spec)) {
			memcpy(tail_param, data, mask->match_sz);
			buff = tail_param;
		} else {
			buff = mask->match_buf;
		}
		dr_ste_copy_mask_spec(buff, &set_param->outer);
	}
	param_location = sizeof(struct dr_match_spec);

	if (match_criteria & DR_MATCHER_CRITERIA_MISC) {
		if (mask->match_sz < param_location +
		    sizeof(struct dr_match_misc)) {
			memcpy(tail_param, data + param_location,
			       mask->match_sz - param_location);
			buff = tail_param;
		} else {
			buff = data + param_location;
		}
		dr_ste_copy_mask_misc(buff, &set_param->misc);
	}
	param_location += sizeof(struct dr_match_misc);

	if (match_criteria & DR_MATCHER_CRITERIA_INNER) {
		if (mask->match_sz < param_location +
		    sizeof(struct dr_match_spec)) {
			memcpy(tail_param, data + param_location,
			       mask->match_sz - param_location);
			buff = tail_param;
		} else {
			buff = data + param_location;
		}
		dr_ste_copy_mask_spec(buff, &set_param->inner);
	}
	param_location += sizeof(struct dr_match_spec);

	if (match_criteria & DR_MATCHER_CRITERIA_MISC2) {
		if (mask->match_sz < param_location +
		    sizeof(struct dr_match_misc2)) {
			memcpy(tail_param, data + param_location,
			       mask->match_sz - param_location);
			buff = tail_param;
		} else {
			buff = data + param_location;
		}
		dr_ste_copy_mask_misc2(buff, &set_param->misc2);
	}

	param_location += sizeof(struct dr_match_misc2);

	if (match_criteria & DR_MATCHER_CRITERIA_MISC3) {
		if (mask->match_sz < param_location +
		    sizeof(struct dr_match_misc3)) {
			memcpy(tail_param, data + param_location,
			       mask->match_sz - param_location);
			buff = tail_param;
		} else {
			buff = data + param_location;
		}
		dr_ste_copy_mask_misc3(buff, &set_param->misc3);
	}
}

static int dr_ste_build_eth_l2_src_des_tag(struct dr_match_param *value,
					   struct dr_ste_build *sb,
					   uint8_t *hw_ste_p)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;
	uint8_t *tag = hw_ste->tag;

	DR_STE_SET_TAG(eth_l2_src_dst, tag, dmac_47_16, spec, dmac_47_16);
	DR_STE_SET_TAG(eth_l2_src_dst, tag, dmac_15_0, spec, dmac_15_0);

	if (spec->smac_47_16 || spec->smac_15_0) {
		DR_STE_SET(eth_l2_src_dst, tag, smac_47_32,
			   spec->smac_47_16 >> 16);
		DR_STE_SET(eth_l2_src_dst, tag, smac_31_0,
			   spec->smac_47_16 << 16 | spec->smac_15_0);
		spec->smac_47_16 = 0;
		spec->smac_15_0 = 0;
	}

	if (spec->ip_version) {
		if (spec->ip_version == IP_VERSION_IPV4) {
			DR_STE_SET(eth_l2_src_dst, tag, l3_type, STE_IPV4);
			spec->ip_version = 0;
		} else if (spec->ip_version == IP_VERSION_IPV6) {
			DR_STE_SET(eth_l2_src_dst, tag, l3_type, STE_IPV6);
			spec->ip_version = 0;
		} else {
			errno = EINVAL;
			return errno;
		}
	}

	DR_STE_SET_TAG(eth_l2_src_dst, tag, first_vlan_id, spec, first_vid);
	DR_STE_SET_TAG(eth_l2_src_dst, tag, first_cfi, spec, first_cfi);
	DR_STE_SET_TAG(eth_l2_src_dst, tag, first_priority, spec, first_prio);

	if (spec->cvlan_tag) {
		DR_STE_SET(eth_l2_src_dst, tag, first_vlan_qualifier, DR_STE_CVLAN);
		spec->cvlan_tag = 0;
	} else if (spec->svlan_tag) {
		DR_STE_SET(eth_l2_src_dst, tag, first_vlan_qualifier, DR_STE_SVLAN);
		spec->svlan_tag = 0;
	}
	return 0;
}

int dr_ste_build_eth_l2_src_des(struct dr_ste_build *sb,
				struct dr_match_param *mask,
				bool inner, bool rx)
{
	int ret;

	ret = dr_ste_build_eth_l2_src_des_bit_mask(mask, inner, sb->bit_mask);
	if (ret)
		return ret;

	sb->rx = rx;
	sb->inner = inner;
	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL2_SRC_DST, rx, inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_build_eth_l2_src_des_tag;

	return 0;
}

static void dr_ste_build_eth_l3_ipv6_dst_bit_mask(struct dr_match_param *value,
						  bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;

	DR_STE_SET_MASK_V(eth_l3_ipv6_dst, bit_mask, dst_ip_127_96, mask, dst_ip_127_96);
	DR_STE_SET_MASK_V(eth_l3_ipv6_dst, bit_mask, dst_ip_95_64, mask, dst_ip_95_64);
	DR_STE_SET_MASK_V(eth_l3_ipv6_dst, bit_mask, dst_ip_63_32, mask, dst_ip_63_32);
	DR_STE_SET_MASK_V(eth_l3_ipv6_dst, bit_mask, dst_ip_31_0, mask, dst_ip_31_0);
}

static int dr_ste_build_eth_l3_ipv6_dst_tag(struct dr_match_param *value,
					    struct dr_ste_build *sb,
					    uint8_t *hw_ste_p)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;
	uint8_t *tag = hw_ste->tag;

	DR_STE_SET_TAG(eth_l3_ipv6_dst, tag, dst_ip_127_96, spec, dst_ip_127_96);
	DR_STE_SET_TAG(eth_l3_ipv6_dst, tag, dst_ip_95_64, spec, dst_ip_95_64);
	DR_STE_SET_TAG(eth_l3_ipv6_dst, tag, dst_ip_63_32, spec, dst_ip_63_32);
	DR_STE_SET_TAG(eth_l3_ipv6_dst, tag, dst_ip_31_0, spec, dst_ip_31_0);

	return 0;
}

void dr_ste_build_eth_l3_ipv6_dst(struct dr_ste_build *sb,
				  struct dr_match_param *mask,
				  bool inner, bool rx)
{
	dr_ste_build_eth_l3_ipv6_dst_bit_mask(mask, inner, sb->bit_mask);

	sb->rx = rx;
	sb->inner = inner;
	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL3_IPV6_DST, rx, inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_build_eth_l3_ipv6_dst_tag;
}

static void dr_ste_build_eth_l3_ipv6_src_bit_mask(struct dr_match_param *value,
						  bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;

	DR_STE_SET_MASK_V(eth_l3_ipv6_src, bit_mask, src_ip_127_96, mask, src_ip_127_96);
	DR_STE_SET_MASK_V(eth_l3_ipv6_src, bit_mask, src_ip_95_64, mask, src_ip_95_64);
	DR_STE_SET_MASK_V(eth_l3_ipv6_src, bit_mask, src_ip_63_32, mask, src_ip_63_32);
	DR_STE_SET_MASK_V(eth_l3_ipv6_src, bit_mask, src_ip_31_0, mask, src_ip_31_0);
}

static int dr_ste_build_eth_l3_ipv6_src_tag(struct dr_match_param *value,
					    struct dr_ste_build *sb,
					    uint8_t *hw_ste_p)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;
	uint8_t *tag = hw_ste->tag;

	DR_STE_SET_TAG(eth_l3_ipv6_src, tag, src_ip_127_96, spec, src_ip_127_96);
	DR_STE_SET_TAG(eth_l3_ipv6_src, tag, src_ip_95_64, spec, src_ip_95_64);
	DR_STE_SET_TAG(eth_l3_ipv6_src, tag, src_ip_63_32, spec, src_ip_63_32);
	DR_STE_SET_TAG(eth_l3_ipv6_src, tag, src_ip_31_0, spec, src_ip_31_0);

	return 0;
}

void dr_ste_build_eth_l3_ipv6_src(struct dr_ste_build *sb,
				  struct dr_match_param *mask,
				  bool inner, bool rx)
{
	dr_ste_build_eth_l3_ipv6_src_bit_mask(mask, inner, sb->bit_mask);

	sb->rx = rx;
	sb->inner = inner;
	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL3_IPV6_SRC, rx, inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_build_eth_l3_ipv6_src_tag;
}

static void dr_ste_build_eth_l3_ipv4_5_tuple_bit_mask(struct dr_match_param *value,
						      bool inner,
						      uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;

	DR_STE_SET_MASK_V(eth_l3_ipv4_5_tuple, bit_mask, destination_address, mask, dst_ip_31_0);
	DR_STE_SET_MASK_V(eth_l3_ipv4_5_tuple, bit_mask, source_address, mask, src_ip_31_0);
	DR_STE_SET_MASK_V(eth_l3_ipv4_5_tuple, bit_mask, destination_port, mask, tcp_dport);
	DR_STE_SET_MASK_V(eth_l3_ipv4_5_tuple, bit_mask, destination_port, mask, udp_dport);
	DR_STE_SET_MASK_V(eth_l3_ipv4_5_tuple, bit_mask, source_port, mask, tcp_sport);
	DR_STE_SET_MASK_V(eth_l3_ipv4_5_tuple, bit_mask, source_port, mask, udp_sport);
	DR_STE_SET_MASK_V(eth_l3_ipv4_5_tuple, bit_mask, protocol, mask, ip_protocol);
	DR_STE_SET_MASK_V(eth_l3_ipv4_5_tuple, bit_mask, fragmented, mask, frag);
	DR_STE_SET_MASK_V(eth_l3_ipv4_5_tuple, bit_mask, dscp, mask, ip_dscp);
	DR_STE_SET_MASK_V(eth_l3_ipv4_5_tuple, bit_mask, ecn, mask, ip_ecn);

	if (mask->tcp_flags) {
		DR_STE_SET_TCP_FLAGS(eth_l3_ipv4_5_tuple, bit_mask, mask);
		mask->tcp_flags = 0;
	}
}

static int dr_ste_build_eth_l3_ipv4_5_tuple_tag(struct dr_match_param *value,
						struct dr_ste_build *sb,
						uint8_t *hw_ste_p)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;
	uint8_t *tag = hw_ste->tag;

	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple, tag, destination_address, spec, dst_ip_31_0);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple, tag, source_address, spec, src_ip_31_0);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple, tag, destination_port, spec, tcp_dport);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple, tag, destination_port, spec, udp_dport);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple, tag, source_port, spec, tcp_sport);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple, tag, source_port, spec, udp_sport);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple, tag, protocol, spec, ip_protocol);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple, tag, fragmented, spec, frag);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple, tag, dscp, spec, ip_dscp);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple, tag, ecn, spec, ip_ecn);

	if (spec->tcp_flags) {
		DR_STE_SET_TCP_FLAGS(eth_l3_ipv4_5_tuple, tag, spec);
		spec->tcp_flags = 0;
	}

	return 0;
}

void dr_ste_build_eth_l3_ipv4_5_tuple(struct dr_ste_build *sb,
				      struct dr_match_param *mask,
				      bool inner, bool rx)
{
	dr_ste_build_eth_l3_ipv4_5_tuple_bit_mask(mask, inner, sb->bit_mask);

	sb->rx = rx;
	sb->inner = inner;
	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL3_IPV4_5_TUPLE, rx, inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_build_eth_l3_ipv4_5_tuple_tag;
}

static void
dr_ste_build_eth_l2_src_or_dst_bit_mask(struct dr_match_param *value,
					bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;
	struct dr_match_misc *misc_mask = &value->misc;

	DR_STE_SET_MASK_V(eth_l2_src, bit_mask, first_vlan_id, mask, first_vid);
	DR_STE_SET_MASK_V(eth_l2_src, bit_mask, first_cfi, mask, first_cfi);
	DR_STE_SET_MASK_V(eth_l2_src, bit_mask, first_priority, mask, first_prio);
	DR_STE_SET_MASK_V(eth_l2_src, bit_mask, ip_fragmented, mask, frag);
	DR_STE_SET_MASK_V(eth_l2_src, bit_mask, l3_ethertype, mask, ethertype);
	DR_STE_SET_MASK(eth_l2_src, bit_mask, l3_type, mask, ip_version);

	if (mask->svlan_tag || mask->cvlan_tag) {
		DR_STE_SET(eth_l2_src, bit_mask, first_vlan_qualifier, -1);
		mask->cvlan_tag = 0;
		mask->svlan_tag = 0;
	}

	if (inner) {
		if (misc_mask->inner_second_cvlan_tag ||
		    misc_mask->inner_second_svlan_tag) {
			DR_STE_SET(eth_l2_src, bit_mask, second_vlan_qualifier, -1);
			misc_mask->inner_second_cvlan_tag = 0;
			misc_mask->inner_second_svlan_tag = 0;
		}

		DR_STE_SET_MASK_V(eth_l2_src, bit_mask, second_vlan_id, misc_mask, inner_second_vid);
		DR_STE_SET_MASK_V(eth_l2_src, bit_mask, second_cfi, misc_mask, inner_second_cfi);
		DR_STE_SET_MASK_V(eth_l2_src, bit_mask, second_priority, misc_mask, inner_second_prio);
	} else {
		if (misc_mask->outer_second_cvlan_tag ||
		    misc_mask->outer_second_svlan_tag) {
			DR_STE_SET(eth_l2_src, bit_mask, second_vlan_qualifier, -1);
			misc_mask->outer_second_cvlan_tag = 0;
			misc_mask->outer_second_svlan_tag = 0;
		}

		DR_STE_SET_MASK_V(eth_l2_src, bit_mask, second_vlan_id, misc_mask, outer_second_vid);
		DR_STE_SET_MASK_V(eth_l2_src, bit_mask, second_cfi, misc_mask, outer_second_cfi);
		DR_STE_SET_MASK_V(eth_l2_src, bit_mask, second_priority, misc_mask, outer_second_prio);
	}
}

static int dr_ste_build_eth_l2_src_or_dst_tag(struct dr_match_param *value,
					      bool inner, uint8_t *hw_ste_p)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	struct dr_match_spec *spec = inner ? &value->inner : &value->outer;
	struct dr_match_misc *misc_spec = &value->misc;
	uint8_t *tag = hw_ste->tag;

	DR_STE_SET_TAG(eth_l2_src, tag, first_vlan_id, spec, first_vid);
	DR_STE_SET_TAG(eth_l2_src, tag, first_cfi, spec, first_cfi);
	DR_STE_SET_TAG(eth_l2_src, tag, first_priority, spec, first_prio);
	DR_STE_SET_TAG(eth_l2_src, tag, ip_fragmented, spec, frag);
	DR_STE_SET_TAG(eth_l2_src, tag, l3_ethertype, spec, ethertype);

	if (spec->ip_version) {
		if (spec->ip_version == IP_VERSION_IPV4) {
			DR_STE_SET(eth_l2_src, tag, l3_type, STE_IPV4);
			spec->ip_version = 0;
		} else if (spec->ip_version == IP_VERSION_IPV6) {
			DR_STE_SET(eth_l2_src, tag, l3_type, STE_IPV6);
			spec->ip_version = 0;
		} else {
			errno = EINVAL;
			return errno;
		}
	}

	if (spec->cvlan_tag) {
		DR_STE_SET(eth_l2_src, tag, first_vlan_qualifier, DR_STE_CVLAN);
		spec->cvlan_tag = 0;
	} else if (spec->svlan_tag) {
		DR_STE_SET(eth_l2_src, tag, first_vlan_qualifier, DR_STE_SVLAN);
		spec->svlan_tag = 0;
	}

	if (inner) {
		if (misc_spec->inner_second_cvlan_tag) {
			DR_STE_SET(eth_l2_src, tag, second_vlan_qualifier, DR_STE_CVLAN);
			misc_spec->inner_second_cvlan_tag = 0;
		} else if (misc_spec->inner_second_svlan_tag) {
			DR_STE_SET(eth_l2_src, tag, second_vlan_qualifier, DR_STE_SVLAN);
			misc_spec->inner_second_svlan_tag = 0;
		}

		DR_STE_SET_TAG(eth_l2_src, tag, second_vlan_id, misc_spec, inner_second_vid);
		DR_STE_SET_TAG(eth_l2_src, tag, second_cfi, misc_spec, inner_second_cfi);
		DR_STE_SET_TAG(eth_l2_src, tag, second_priority, misc_spec, inner_second_prio);
	} else {
		if (misc_spec->outer_second_cvlan_tag) {
			DR_STE_SET(eth_l2_src, tag, second_vlan_qualifier, DR_STE_CVLAN);
			misc_spec->outer_second_cvlan_tag = 0;
		} else if (misc_spec->outer_second_svlan_tag) {
			DR_STE_SET(eth_l2_src, tag, second_vlan_qualifier, DR_STE_SVLAN);
			misc_spec->outer_second_svlan_tag = 0;
		}
		DR_STE_SET_TAG(eth_l2_src, tag, second_vlan_id, misc_spec, outer_second_vid);
		DR_STE_SET_TAG(eth_l2_src, tag, second_cfi, misc_spec, outer_second_cfi);
		DR_STE_SET_TAG(eth_l2_src, tag, second_priority, misc_spec, outer_second_prio);
	}

	return 0;
}

static void dr_ste_build_eth_l2_src_bit_mask(struct dr_match_param *value,
					     bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;

	DR_STE_SET_MASK_V(eth_l2_src, bit_mask, smac_47_16, mask, smac_47_16);
	DR_STE_SET_MASK_V(eth_l2_src, bit_mask, smac_15_0, mask, smac_15_0);

	dr_ste_build_eth_l2_src_or_dst_bit_mask(value, inner, bit_mask);
}

static int dr_ste_build_eth_l2_src_tag(struct dr_match_param *value,
				       struct dr_ste_build *sb,
				       uint8_t *hw_ste_p)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;
	uint8_t *tag = hw_ste->tag;

	DR_STE_SET_TAG(eth_l2_src, tag, smac_47_16, spec, smac_47_16);
	DR_STE_SET_TAG(eth_l2_src, tag, smac_15_0, spec, smac_15_0);

	return dr_ste_build_eth_l2_src_or_dst_tag(value, sb->inner, hw_ste_p);
}

void dr_ste_build_eth_l2_src(struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx)
{
	dr_ste_build_eth_l2_src_bit_mask(mask, inner, sb->bit_mask);

	sb->rx = rx;
	sb->inner = inner;
	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL2_SRC, rx, inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_build_eth_l2_src_tag;
}

static void dr_ste_build_eth_l2_dst_bit_mask(struct dr_match_param *value,
					     bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;

	DR_STE_SET_MASK_V(eth_l2_dst, bit_mask, dmac_47_16, mask, dmac_47_16);
	DR_STE_SET_MASK_V(eth_l2_dst, bit_mask, dmac_15_0, mask, dmac_15_0);

	dr_ste_build_eth_l2_src_or_dst_bit_mask(value, inner, bit_mask);
}

static int dr_ste_build_eth_l2_dst_tag(struct dr_match_param *value,
				       struct dr_ste_build *sb,
				       uint8_t *hw_ste_p)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;
	uint8_t *tag = hw_ste->tag;

	DR_STE_SET_TAG(eth_l2_dst, tag, dmac_47_16, spec, dmac_47_16);
	DR_STE_SET_TAG(eth_l2_dst, tag, dmac_15_0, spec, dmac_15_0);

	return dr_ste_build_eth_l2_src_or_dst_tag(value, sb->inner, hw_ste_p);
}

void dr_ste_build_eth_l2_dst(struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx)
{
	dr_ste_build_eth_l2_dst_bit_mask(mask, inner, sb->bit_mask);

	sb->rx = rx;
	sb->inner = inner;
	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL2_DST, rx, inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_build_eth_l2_dst_tag;
}

static void dr_ste_build_eth_l2_tnl_bit_mask(struct dr_match_param *value,
					     bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;
	struct dr_match_misc *misc = &value->misc;

	DR_STE_SET_MASK_V(eth_l2_tnl, bit_mask, dmac_47_16, mask, dmac_47_16);
	DR_STE_SET_MASK_V(eth_l2_tnl, bit_mask, dmac_15_0, mask, dmac_15_0);
	DR_STE_SET_MASK_V(eth_l2_tnl, bit_mask, first_vlan_id, mask, first_vid);
	DR_STE_SET_MASK_V(eth_l2_tnl, bit_mask, first_cfi, mask, first_cfi);
	DR_STE_SET_MASK_V(eth_l2_tnl, bit_mask, first_priority, mask, first_prio);
	DR_STE_SET_MASK_V(eth_l2_tnl, bit_mask, ip_fragmented, mask, frag);
	DR_STE_SET_MASK_V(eth_l2_tnl, bit_mask, l3_ethertype, mask, ethertype);
	DR_STE_SET_MASK(eth_l2_tnl, bit_mask, l3_type, mask, ip_version);

	if (misc->vxlan_vni) {
		DR_STE_SET(eth_l2_tnl, bit_mask, l2_tunneling_network_id, (misc->vxlan_vni << 8));
		misc->vxlan_vni = 0;
	}

	if (mask->svlan_tag || mask->cvlan_tag) {
		DR_STE_SET(eth_l2_tnl, bit_mask, first_vlan_qualifier, -1);
		mask->cvlan_tag = 0;
		mask->svlan_tag = 0;
	}
}

static int dr_ste_build_eth_l2_tnl_tag(struct dr_match_param *value,
				       struct dr_ste_build *sb,
				       uint8_t *hw_ste_p)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;
	struct dr_match_misc *misc = &value->misc;
	uint8_t *tag = hw_ste->tag;

	DR_STE_SET_TAG(eth_l2_tnl, tag, dmac_47_16, spec, dmac_47_16);
	DR_STE_SET_TAG(eth_l2_tnl, tag, dmac_15_0, spec, dmac_15_0);
	DR_STE_SET_TAG(eth_l2_tnl, tag, first_vlan_id, spec, first_vid);
	DR_STE_SET_TAG(eth_l2_tnl, tag, first_cfi, spec, first_cfi);
	DR_STE_SET_TAG(eth_l2_tnl, tag, ip_fragmented, spec, frag);
	DR_STE_SET_TAG(eth_l2_tnl, tag, first_priority, spec, first_prio);
	DR_STE_SET_TAG(eth_l2_tnl, tag, l3_ethertype, spec, ethertype);

	if (misc->vxlan_vni) {
		DR_STE_SET(eth_l2_tnl, tag, l2_tunneling_network_id,
			   (misc->vxlan_vni << 8));
		misc->vxlan_vni = 0;
	}

	if (spec->cvlan_tag) {
		DR_STE_SET(eth_l2_tnl, tag, first_vlan_qualifier, DR_STE_CVLAN);
		spec->cvlan_tag = 0;
	} else if (spec->svlan_tag) {
		DR_STE_SET(eth_l2_tnl, tag, first_vlan_qualifier, DR_STE_SVLAN);
		spec->svlan_tag = 0;
	}

	if (spec->ip_version) {
		if (spec->ip_version == IP_VERSION_IPV4) {
			DR_STE_SET(eth_l2_tnl, tag, l3_type, STE_IPV4);
			spec->ip_version = 0;
		} else if (spec->ip_version == IP_VERSION_IPV6) {
			DR_STE_SET(eth_l2_tnl, tag, l3_type, STE_IPV6);
			spec->ip_version = 0;
		} else {
			errno = EINVAL;
			return errno;
		}
	}

	return 0;
}

void dr_ste_build_eth_l2_tnl(struct dr_ste_build *sb,
			     struct dr_match_param *mask, bool inner, bool rx)
{
	dr_ste_build_eth_l2_tnl_bit_mask(mask, inner, sb->bit_mask);

	sb->rx = rx;
	sb->inner = inner;
	sb->lu_type = DR_STE_LU_TYPE_ETHL2_TUNNELING_I;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_build_eth_l2_tnl_tag;
}

static void dr_ste_build_eth_l3_ipv4_misc_bit_mask(struct dr_match_param *value,
						   bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;

	DR_STE_SET_MASK_V(eth_l3_ipv4_misc, bit_mask, time_to_live, mask, ip_ttl_hoplimit);
}

static int dr_ste_build_eth_l3_ipv4_misc_tag(struct dr_match_param *value,
					     struct dr_ste_build *sb,
					     uint8_t *hw_ste_p)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;
	uint8_t *tag = hw_ste->tag;

	DR_STE_SET_TAG(eth_l3_ipv4_misc, tag, time_to_live, spec, ip_ttl_hoplimit);

	return 0;
}

void dr_ste_build_eth_l3_ipv4_misc(struct dr_ste_build *sb,
				   struct dr_match_param *mask,
				   bool inner, bool rx)
{
	dr_ste_build_eth_l3_ipv4_misc_bit_mask(mask, inner, sb->bit_mask);

	sb->rx = rx;
	sb->inner = inner;
	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL3_IPV4_MISC, rx, inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_build_eth_l3_ipv4_misc_tag;
}

static void dr_ste_build_ipv6_l3_l4_bit_mask(struct dr_match_param *value,
					     bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;

	DR_STE_SET_MASK_V(eth_l4, bit_mask, dst_port, mask, tcp_dport);
	DR_STE_SET_MASK_V(eth_l4, bit_mask, src_port, mask, tcp_sport);
	DR_STE_SET_MASK_V(eth_l4, bit_mask, dst_port, mask, udp_dport);
	DR_STE_SET_MASK_V(eth_l4, bit_mask, src_port, mask, udp_sport);
	DR_STE_SET_MASK_V(eth_l4, bit_mask, protocol, mask, ip_protocol);
	DR_STE_SET_MASK_V(eth_l4, bit_mask, fragmented, mask, frag);
	DR_STE_SET_MASK_V(eth_l4, bit_mask, dscp, mask, ip_dscp);
	DR_STE_SET_MASK_V(eth_l4, bit_mask, ecn, mask, ip_ecn);
	DR_STE_SET_MASK_V(eth_l4, bit_mask, ipv6_hop_limit, mask, ip_ttl_hoplimit);

	if (mask->tcp_flags) {
		DR_STE_SET_TCP_FLAGS(eth_l4, bit_mask, mask);
		mask->tcp_flags = 0;
	}
}

static int dr_ste_build_ipv6_l3_l4_tag(struct dr_match_param *value,
				       struct dr_ste_build *sb,
				       uint8_t *hw_ste_p)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;
	uint8_t *tag = hw_ste->tag;

	DR_STE_SET_TAG(eth_l4, tag, dst_port, spec, tcp_dport);
	DR_STE_SET_TAG(eth_l4, tag, src_port, spec, tcp_sport);
	DR_STE_SET_TAG(eth_l4, tag, dst_port, spec, udp_dport);
	DR_STE_SET_TAG(eth_l4, tag, src_port, spec, udp_sport);
	DR_STE_SET_TAG(eth_l4, tag, protocol, spec, ip_protocol);
	DR_STE_SET_TAG(eth_l4, tag, fragmented, spec, frag);
	DR_STE_SET_TAG(eth_l4, tag, dscp, spec, ip_dscp);
	DR_STE_SET_TAG(eth_l4, tag, ecn, spec, ip_ecn);
	DR_STE_SET_TAG(eth_l4, tag, ipv6_hop_limit, spec, ip_ttl_hoplimit);

	if (spec->tcp_flags) {
		DR_STE_SET_TCP_FLAGS(eth_l4, tag, spec);
		spec->tcp_flags = 0;
	}

	return 0;
}

void dr_ste_build_ipv6_l3_l4(struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx)
{
	dr_ste_build_ipv6_l3_l4_bit_mask(mask, inner, sb->bit_mask);

	sb->rx = rx;
	sb->inner = inner;
	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL4, rx, inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_build_ipv6_l3_l4_tag;
}

static int dr_ste_build_empty_always_hit_tag(struct dr_match_param *value,
					     struct dr_ste_build *sb,
					     uint8_t *hw_ste_p)
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

static void dr_ste_build_mpls_bit_mask(struct dr_match_param *value,
				       bool inner, uint8_t *bit_mask)
{
	struct dr_match_misc2 *misc2_mask = &value->misc2;

	if (inner)
		DR_STE_SET_MPLS_MASK(mpls, misc2_mask, inner, bit_mask);
	else
		DR_STE_SET_MPLS_MASK(mpls, misc2_mask, outer, bit_mask);
}

static int dr_ste_build_mpls_tag(struct dr_match_param *value,
				 struct dr_ste_build *sb,
				 uint8_t *hw_ste_p)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	struct dr_match_misc2 *misc2_mask = &value->misc2;
	uint8_t *tag = hw_ste->tag;

	if (sb->inner)
		DR_STE_SET_MPLS_TAG(mpls, misc2_mask, inner, tag);
	else
		DR_STE_SET_MPLS_TAG(mpls, misc2_mask, outer, tag);

	return 0;
}

void dr_ste_build_mpls(struct dr_ste_build *sb, struct dr_match_param *mask,
		       bool inner, bool rx)
{
	dr_ste_build_mpls_bit_mask(mask, inner, sb->bit_mask);

	sb->rx = rx;
	sb->inner = inner;
	sb->lu_type = DR_STE_CALC_LU_TYPE(MPLS_FIRST, rx, inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_build_mpls_tag;
}

static void dr_ste_build_gre_bit_mask(struct dr_match_param *value,
				      bool inner, uint8_t *bit_mask)
{
	struct dr_match_misc *misc_mask = &value->misc;

	DR_STE_SET_MASK_V(gre, bit_mask, gre_protocol, misc_mask, gre_protocol);
	DR_STE_SET_MASK_V(gre, bit_mask, gre_k_present, misc_mask, gre_k_present);
	DR_STE_SET_MASK_V(gre, bit_mask, gre_key_h, misc_mask, gre_key_h);
	DR_STE_SET_MASK_V(gre, bit_mask, gre_key_l, misc_mask, gre_key_l);

	DR_STE_SET_MASK_V(gre, bit_mask, gre_c_present, misc_mask, gre_c_present);
	DR_STE_SET_MASK_V(gre, bit_mask, gre_s_present, misc_mask, gre_s_present);
}

static int dr_ste_build_gre_tag(struct dr_match_param *value,
				struct dr_ste_build *sb,
				uint8_t *hw_ste_p)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	struct  dr_match_misc *misc = &value->misc;
	uint8_t *tag = hw_ste->tag;

	DR_STE_SET_TAG(gre, tag, gre_protocol, misc, gre_protocol);

	DR_STE_SET_TAG(gre, tag, gre_k_present, misc, gre_k_present);
	DR_STE_SET_TAG(gre, tag, gre_key_h, misc, gre_key_h);
	DR_STE_SET_TAG(gre, tag, gre_key_l, misc, gre_key_l);

	DR_STE_SET_TAG(gre, tag, gre_c_present, misc, gre_c_present);

	DR_STE_SET_TAG(gre, tag, gre_s_present, misc, gre_s_present);

	return 0;
}

void dr_ste_build_gre(struct dr_ste_build *sb, struct dr_match_param *mask,
		      bool inner, bool rx)
{
	dr_ste_build_gre_bit_mask(mask, inner, sb->bit_mask);

	sb->rx = rx;
	sb->inner = inner;
	sb->lu_type = DR_STE_LU_TYPE_GRE;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_build_gre_tag;
}

static void dr_ste_build_flex_parser_0_bit_mask(struct dr_match_param *value,
						bool inner, uint8_t *bit_mask)
{
	struct dr_match_misc2 *misc_2_mask = &value->misc2;

	if (DR_STE_IS_OUTER_MPLS_OVER_GRE_SET(misc_2_mask)) {
		DR_STE_SET_MASK_V(flex_parser_0, bit_mask, parser_3_label,
				  misc_2_mask, outer_first_mpls_over_gre_label);

		DR_STE_SET_MASK_V(flex_parser_0, bit_mask, parser_3_exp,
				  misc_2_mask, outer_first_mpls_over_gre_exp);

		DR_STE_SET_MASK_V(flex_parser_0, bit_mask, parser_3_s_bos,
				  misc_2_mask, outer_first_mpls_over_gre_s_bos);

		DR_STE_SET_MASK_V(flex_parser_0, bit_mask, parser_3_ttl,
				  misc_2_mask, outer_first_mpls_over_gre_ttl);
	} else {
		DR_STE_SET_MASK_V(flex_parser_0, bit_mask, parser_3_label,
				  misc_2_mask, outer_first_mpls_over_udp_label);

		DR_STE_SET_MASK_V(flex_parser_0, bit_mask, parser_3_exp,
				  misc_2_mask, outer_first_mpls_over_udp_exp);

		DR_STE_SET_MASK_V(flex_parser_0, bit_mask, parser_3_s_bos,
				  misc_2_mask, outer_first_mpls_over_udp_s_bos);

		DR_STE_SET_MASK_V(flex_parser_0, bit_mask, parser_3_ttl,
				  misc_2_mask, outer_first_mpls_over_udp_ttl);
	}
}

static int dr_ste_build_flex_parser_0_tag(struct dr_match_param *value,
					  struct dr_ste_build *sb,
					  uint8_t *hw_ste_p)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	struct dr_match_misc2 *misc_2_mask = &value->misc2;
	uint8_t *tag = hw_ste->tag;

	if (DR_STE_IS_OUTER_MPLS_OVER_GRE_SET(misc_2_mask)) {
		DR_STE_SET_TAG(flex_parser_0, tag, parser_3_label,
			       misc_2_mask, outer_first_mpls_over_gre_label);

		DR_STE_SET_TAG(flex_parser_0, tag, parser_3_exp,
			       misc_2_mask, outer_first_mpls_over_gre_exp);

		DR_STE_SET_TAG(flex_parser_0, tag, parser_3_s_bos,
			       misc_2_mask, outer_first_mpls_over_gre_s_bos);

		DR_STE_SET_TAG(flex_parser_0, tag, parser_3_ttl,
			       misc_2_mask, outer_first_mpls_over_gre_ttl);
	} else {
		DR_STE_SET_TAG(flex_parser_0, tag, parser_3_label,
			       misc_2_mask, outer_first_mpls_over_udp_label);

		DR_STE_SET_TAG(flex_parser_0, tag, parser_3_exp,
			       misc_2_mask, outer_first_mpls_over_udp_exp);

		DR_STE_SET_TAG(flex_parser_0, tag, parser_3_s_bos,
			       misc_2_mask, outer_first_mpls_over_udp_s_bos);

		DR_STE_SET_TAG(flex_parser_0, tag, parser_3_ttl,
			       misc_2_mask, outer_first_mpls_over_udp_ttl);
	}
	return 0;
}

void dr_ste_build_flex_parser_0(struct dr_ste_build *sb,
				struct dr_match_param *mask,
				bool inner, bool rx)
{
	dr_ste_build_flex_parser_0_bit_mask(mask, inner, sb->bit_mask);

	sb->rx = rx;
	sb->inner = inner;
	sb->lu_type = DR_STE_LU_TYPE_FLEX_PARSER_0;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_build_flex_parser_0_tag;
}

#define ICMP_TYPE_OFFSET_FIRST_DW		24
#define ICMP_CODE_OFFSET_FIRST_DW		16
#define ICMP_HEADER_DATA_OFFSET_SECOND_DW	0

static int dr_ste_build_flex_parser_1_bit_mask(struct dr_match_param *mask,
					       struct dr_devx_caps *caps,
					       uint8_t *bit_mask)
{
	struct dr_match_misc3 *misc_3_mask = &mask->misc3;
	bool is_ipv4_mask = DR_MASK_IS_FLEX_PARSER_ICMPV4_SET(misc_3_mask);
	uint32_t icmp_header_data_mask;
	uint32_t icmp_type_mask;
	uint32_t icmp_code_mask;
	int dw0_location;
	int dw1_location;

	if (is_ipv4_mask) {
		icmp_header_data_mask	= misc_3_mask->icmpv4_header_data;
		icmp_type_mask		= misc_3_mask->icmpv4_type;
		icmp_code_mask		= misc_3_mask->icmpv4_code;
		dw0_location		= caps->flex_parser_id_icmp_dw0;
		dw1_location		= caps->flex_parser_id_icmp_dw1;
	} else {
		icmp_header_data_mask	= misc_3_mask->icmpv6_header_data;
		icmp_type_mask		= misc_3_mask->icmpv6_type;
		icmp_code_mask		= misc_3_mask->icmpv6_code;
		dw0_location		= caps->flex_parser_id_icmpv6_dw0;
		dw1_location		= caps->flex_parser_id_icmpv6_dw1;
	}

	switch (dw0_location) {
	case 4:
		if (icmp_type_mask) {
			DR_STE_SET(flex_parser_1, bit_mask, flex_parser_4,
				   (icmp_type_mask << ICMP_TYPE_OFFSET_FIRST_DW));
			if (is_ipv4_mask)
				misc_3_mask->icmpv4_type = 0;
			else
				misc_3_mask->icmpv6_type = 0;
		}
		if (icmp_code_mask) {
			uint32_t cur_val = DR_STE_GET(flex_parser_1, bit_mask,
						      flex_parser_4);
			DR_STE_SET(flex_parser_1, bit_mask, flex_parser_4,
				   cur_val | (icmp_code_mask << ICMP_CODE_OFFSET_FIRST_DW));
			if (is_ipv4_mask)
				misc_3_mask->icmpv4_code = 0;
			else
				misc_3_mask->icmpv6_code = 0;
		}
		break;
	default:
		errno = ENOTSUP;
		return errno;
	}

	switch (dw1_location) {
	case 5:
		if (icmp_header_data_mask) {
			DR_STE_SET(flex_parser_1, bit_mask, flex_parser_5,
				   (icmp_header_data_mask << ICMP_HEADER_DATA_OFFSET_SECOND_DW));
			if (is_ipv4_mask)
				misc_3_mask->icmpv4_header_data = 0;
			else
				misc_3_mask->icmpv6_header_data = 0;
		}
		break;
	default:
		errno = ENOTSUP;
		return errno;
	}

	return 0;
}

static int dr_ste_build_flex_parser_1_tag(struct dr_match_param *value,
					  struct dr_ste_build *sb,
					  uint8_t *hw_ste_p)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	struct dr_match_misc3 *misc_3 = &value->misc3;
	bool is_ipv4 = DR_MASK_IS_FLEX_PARSER_ICMPV4_SET(misc_3);
	uint8_t *tag = hw_ste->tag;
	uint32_t icmp_header_data;
	uint32_t icmp_type;
	uint32_t icmp_code;
	int dw0_location;
	int dw1_location;

	if (is_ipv4) {
		icmp_header_data	= misc_3->icmpv4_header_data;
		icmp_type		= misc_3->icmpv4_type;
		icmp_code		= misc_3->icmpv4_code;
		dw0_location		= sb->caps->flex_parser_id_icmp_dw0;
		dw1_location		= sb->caps->flex_parser_id_icmp_dw1;
	} else {
		icmp_header_data	= misc_3->icmpv6_header_data;
		icmp_type		= misc_3->icmpv6_type;
		icmp_code		= misc_3->icmpv6_code;
		dw0_location		= sb->caps->flex_parser_id_icmpv6_dw0;
		dw1_location		= sb->caps->flex_parser_id_icmpv6_dw1;
	}

	switch (dw0_location) {
	case 4:
		if (icmp_type) {
			DR_STE_SET(flex_parser_1, tag, flex_parser_4,
				   (icmp_type << ICMP_TYPE_OFFSET_FIRST_DW));
			if (is_ipv4)
				misc_3->icmpv4_type = 0;
			else
				misc_3->icmpv6_type = 0;
		}

		if (icmp_code) {
			uint32_t cur_val = DR_STE_GET(flex_parser_1, tag,
						      flex_parser_4);
			DR_STE_SET(flex_parser_1, tag, flex_parser_4,
				   cur_val | (icmp_code << ICMP_CODE_OFFSET_FIRST_DW));
			if (is_ipv4)
				misc_3->icmpv4_code = 0;
			else
				misc_3->icmpv6_code = 0;
		}
		break;
	default:
		errno = ENOTSUP;
		return errno;
	}

	switch (dw1_location) {
	case 5:
		if (icmp_header_data) {
			DR_STE_SET(flex_parser_1, tag, flex_parser_5,
				   (icmp_header_data << ICMP_HEADER_DATA_OFFSET_SECOND_DW));
			if (is_ipv4)
				misc_3->icmpv4_header_data = 0;
			else
				misc_3->icmpv6_header_data = 0;
		}
		break;
	default:
		errno = ENOTSUP;
		return errno;
	}

	return 0;
}

int dr_ste_build_flex_parser_1(struct dr_ste_build *sb,
			       struct dr_match_param *mask,
			       struct dr_devx_caps *caps,
			       bool inner, bool rx)
{
	int ret;

	ret = dr_ste_build_flex_parser_1_bit_mask(mask, caps, sb->bit_mask);
	if (ret)
		return ret;

	sb->rx = rx;
	sb->inner = inner;
	sb->caps = caps;
	sb->lu_type = DR_STE_LU_TYPE_FLEX_PARSER_1;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_build_flex_parser_1_tag;

	return 0;
}

static void dr_ste_build_general_purpose_bit_mask(struct dr_match_param *value,
						  bool inner, uint8_t *bit_mask)
{
	struct dr_match_misc2 *misc_2_mask = &value->misc2;

	DR_STE_SET_MASK_V(general_purpose, bit_mask,
			  general_purpose_lookup_field, misc_2_mask,
			  metadata_reg_a);
}

static int dr_ste_build_general_purpose_tag(struct dr_match_param *value,
					    struct dr_ste_build *sb,
					    uint8_t *hw_ste_p)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	struct dr_match_misc2 *misc_2_mask = &value->misc2;
	uint8_t *tag = hw_ste->tag;

	DR_STE_SET_TAG(general_purpose, tag, general_purpose_lookup_field,
		       misc_2_mask, metadata_reg_a);

	return 0;
}

void dr_ste_build_general_purpose(struct dr_ste_build *sb,
				  struct dr_match_param *mask,
				  bool inner, bool rx)
{
	dr_ste_build_general_purpose_bit_mask(mask, inner, sb->bit_mask);

	sb->rx = rx;
	sb->inner = inner;
	sb->lu_type = DR_STE_LU_TYPE_GENERAL_PURPOSE;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_build_general_purpose_tag;
}

static void dr_ste_build_eth_l4_misc_bit_mask(struct dr_match_param *value,
					      bool inner, uint8_t *bit_mask)
{
	struct dr_match_misc3 *misc_3_mask = &value->misc3;

	if (inner) {
		DR_STE_SET_MASK_V(eth_l4_misc, bit_mask, seq_num, misc_3_mask,
				  inner_tcp_seq_num);
		DR_STE_SET_MASK_V(eth_l4_misc, bit_mask, ack_num, misc_3_mask,
				  inner_tcp_ack_num);
	} else {
		DR_STE_SET_MASK_V(eth_l4_misc, bit_mask, seq_num, misc_3_mask,
				  outer_tcp_seq_num);
		DR_STE_SET_MASK_V(eth_l4_misc, bit_mask, ack_num, misc_3_mask,
				  outer_tcp_ack_num);
	}
}

static int dr_ste_build_eth_l4_misc_tag(struct dr_match_param *value,
					struct dr_ste_build *sb,
					uint8_t *hw_ste_p)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	struct dr_match_misc3 *misc3 = &value->misc3;
	uint8_t *tag = hw_ste->tag;

	if (sb->inner) {
		DR_STE_SET_TAG(eth_l4_misc, tag, seq_num, misc3, inner_tcp_seq_num);
		DR_STE_SET_TAG(eth_l4_misc, tag, ack_num, misc3, inner_tcp_ack_num);
	} else {
		DR_STE_SET_TAG(eth_l4_misc, tag, seq_num, misc3, outer_tcp_seq_num);
		DR_STE_SET_TAG(eth_l4_misc, tag, ack_num, misc3, outer_tcp_ack_num);
	}

	return 0;
}

void dr_ste_build_eth_l4_misc(struct dr_ste_build *sb,
			      struct dr_match_param *mask,
			      bool inner, bool rx)
{
	dr_ste_build_eth_l4_misc_bit_mask(mask, inner, sb->bit_mask);

	sb->rx = rx;
	sb->inner = inner;
	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL4_MISC, rx, inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_build_eth_l4_misc_tag;
}

static void dr_ste_build_flex_parser_tnl_bit_mask(struct dr_match_param *value,
						  bool inner, uint8_t *bit_mask)
{
	struct dr_match_misc3 *misc_3_mask = &value->misc3;

	if (misc_3_mask->outer_vxlan_gpe_flags ||
	    misc_3_mask->outer_vxlan_gpe_next_protocol) {
		DR_STE_SET(flex_parser_tnl, bit_mask,
			   flex_parser_tunneling_header_63_32,
			   (misc_3_mask->outer_vxlan_gpe_flags << 24) |
			   (misc_3_mask->outer_vxlan_gpe_next_protocol));
		misc_3_mask->outer_vxlan_gpe_flags = 0;
		misc_3_mask->outer_vxlan_gpe_next_protocol = 0;
	}

	if (misc_3_mask->outer_vxlan_gpe_vni) {
		DR_STE_SET(flex_parser_tnl, bit_mask,
			   flex_parser_tunneling_header_31_0,
			   misc_3_mask->outer_vxlan_gpe_vni << 8);
		misc_3_mask->outer_vxlan_gpe_vni = 0;
	}
}

static int dr_ste_build_flex_parser_tnl_tag(struct dr_match_param *value,
					    struct dr_ste_build *sb,
					    uint8_t *hw_ste_p)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	struct dr_match_misc3 *misc3 = &value->misc3;
	uint8_t *tag = hw_ste->tag;

	if (misc3->outer_vxlan_gpe_flags ||
	    misc3->outer_vxlan_gpe_next_protocol) {
		DR_STE_SET(flex_parser_tnl, tag,
			   flex_parser_tunneling_header_63_32,
			   (misc3->outer_vxlan_gpe_flags << 24) |
			   (misc3->outer_vxlan_gpe_next_protocol));
		misc3->outer_vxlan_gpe_flags = 0;
		misc3->outer_vxlan_gpe_next_protocol = 0;
	}

	if (misc3->outer_vxlan_gpe_vni) {
		DR_STE_SET(flex_parser_tnl, tag,
			   flex_parser_tunneling_header_31_0,
			   misc3->outer_vxlan_gpe_vni << 8);
		misc3->outer_vxlan_gpe_vni = 0;
	}

	return 0;
}

void dr_ste_build_flex_parser_tnl(struct dr_ste_build *sb,
				  struct dr_match_param *mask,
				  bool inner, bool rx)
{
	dr_ste_build_flex_parser_tnl_bit_mask(mask, inner, sb->bit_mask);

	sb->rx = rx;
	sb->inner = inner;
	sb->lu_type = DR_STE_LU_TYPE_FLEX_PARSER_TNL_HEADER;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_build_flex_parser_tnl_tag;
}

static void dr_ste_build_register_0_bit_mask(struct dr_match_param *value,
					     uint8_t *bit_mask)
{
	struct dr_match_misc2 *misc_2_mask = &value->misc2;

	DR_STE_SET_MASK_V(register_0, bit_mask, register_0_h,
			  misc_2_mask, metadata_reg_c_0);
	DR_STE_SET_MASK_V(register_0, bit_mask, register_0_l,
			  misc_2_mask, metadata_reg_c_1);
	DR_STE_SET_MASK_V(register_0, bit_mask, register_1_h,
			  misc_2_mask, metadata_reg_c_2);
	DR_STE_SET_MASK_V(register_0, bit_mask, register_1_l,
			  misc_2_mask, metadata_reg_c_3);
}

static int dr_ste_build_register_0_tag(struct dr_match_param *value,
				       struct dr_ste_build *sb,
				       uint8_t *hw_ste_p)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	struct dr_match_misc2 *misc2 = &value->misc2;
	uint8_t *tag = hw_ste->tag;

	DR_STE_SET_TAG(register_0, tag, register_0_h, misc2, metadata_reg_c_0);
	DR_STE_SET_TAG(register_0, tag, register_0_l, misc2, metadata_reg_c_1);
	DR_STE_SET_TAG(register_0, tag, register_1_h, misc2, metadata_reg_c_2);
	DR_STE_SET_TAG(register_0, tag, register_1_l, misc2, metadata_reg_c_3);

	return 0;
}

void dr_ste_build_register_0(struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx)
{
	dr_ste_build_register_0_bit_mask(mask, sb->bit_mask);

	sb->rx = rx;
	sb->inner = inner;
	sb->lu_type = DR_STE_LU_TYPE_STEERING_REGISTERS_0;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_build_register_0_tag;
}

static void dr_ste_build_register_1_bit_mask(struct dr_match_param *value,
					     uint8_t *bit_mask)
{
	struct dr_match_misc2 *misc_2_mask = &value->misc2;

	DR_STE_SET_MASK_V(register_1, bit_mask, register_2_h,
			  misc_2_mask, metadata_reg_c_4);
	DR_STE_SET_MASK_V(register_1, bit_mask, register_2_l,
			  misc_2_mask, metadata_reg_c_5);
	DR_STE_SET_MASK_V(register_1, bit_mask, register_3_h,
			  misc_2_mask, metadata_reg_c_6);
	DR_STE_SET_MASK_V(register_1, bit_mask, register_3_l,
			  misc_2_mask, metadata_reg_c_7);
}

static int dr_ste_build_register_1_tag(struct dr_match_param *value,
				       struct dr_ste_build *sb,
				       uint8_t *hw_ste_p)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	struct dr_match_misc2 *misc2 = &value->misc2;
	uint8_t *tag = hw_ste->tag;

	DR_STE_SET_TAG(register_1, tag, register_2_h, misc2, metadata_reg_c_4);
	DR_STE_SET_TAG(register_1, tag, register_2_l, misc2, metadata_reg_c_5);
	DR_STE_SET_TAG(register_1, tag, register_3_h, misc2, metadata_reg_c_6);
	DR_STE_SET_TAG(register_1, tag, register_3_l, misc2, metadata_reg_c_7);

	return 0;
}

void dr_ste_build_register_1(struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx)
{
	dr_ste_build_register_1_bit_mask(mask, sb->bit_mask);

	sb->rx = rx;
	sb->inner = inner;
	sb->lu_type = DR_STE_LU_TYPE_STEERING_REGISTERS_1;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_build_register_1_tag;
}

static int dr_ste_build_src_gvmi_qpn_bit_mask(struct dr_match_param *value,
					      uint8_t *bit_mask)
{
	struct dr_match_misc *misc_mask = &value->misc;

	if (misc_mask->source_port && misc_mask->source_port != 0xffff) {
		errno = EINVAL;
		return errno;
	}
	DR_STE_SET_MASK(src_gvmi_qp, bit_mask, source_gvmi, misc_mask, source_port);
	DR_STE_SET_MASK(src_gvmi_qp, bit_mask, source_qp, misc_mask, source_sqn);

	return 0;
}

static int dr_ste_build_src_gvmi_qpn_tag(struct dr_match_param *value,
					 struct dr_ste_build *sb,
					 uint8_t *hw_ste_p)
{
	struct dr_hw_ste_format *hw_ste = (struct dr_hw_ste_format *)hw_ste_p;
	struct dr_match_misc *misc = &value->misc;
	struct dr_devx_vport_cap *vport_cap;
	uint8_t *tag = hw_ste->tag;

	DR_STE_SET_TAG(src_gvmi_qp, tag, source_qp, misc, source_sqn);

	vport_cap = dr_get_vport_cap(sb->caps, misc->source_port);
	if (!vport_cap)
		return errno;

	if (vport_cap->gvmi)
		DR_STE_SET(src_gvmi_qp, tag, source_gvmi, vport_cap->gvmi);

	misc->source_port = 0;

	return 0;
}

int dr_ste_build_src_gvmi_qpn(struct dr_ste_build *sb,
			      struct dr_match_param *mask,
			      struct dr_devx_caps *caps,
			      bool inner, bool rx)
{
	int ret;

	ret = dr_ste_build_src_gvmi_qpn_bit_mask(mask, sb->bit_mask);
	if (ret)
		return ret;

	sb->rx = rx;
	sb->caps = caps;
	sb->inner = inner;
	sb->lu_type = DR_STE_LU_TYPE_SRC_GVMI_AND_QP;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_build_src_gvmi_qpn_tag;

	return 0;
}
