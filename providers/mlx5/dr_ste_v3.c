/*
 * Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "dr_ste_v1.h"

static void dr_ste_v3_set_encap(uint8_t *hw_ste_p, uint8_t *d_action,
				uint32_t reformat_id, int size)
{
	DR_STE_SET(double_action_insert_with_ptr_v3, d_action, action_id,
		   DR_STE_V1_ACTION_ID_INSERT_POINTER);
	/* The hardware expects here size in words (2 bytes) */
	DR_STE_SET(double_action_insert_with_ptr_v3, d_action, size, size / 2);
	DR_STE_SET(double_action_insert_with_ptr_v3, d_action, pointer, reformat_id);
	DR_STE_SET(double_action_insert_with_ptr_v3, d_action, attributes,
		   DR_STE_V1_ACTION_INSERT_PTR_ATTR_ENCAP);

	dr_ste_v1_set_reparse(hw_ste_p);
}

static void dr_ste_v3_set_push_vlan(uint8_t *ste, uint8_t *d_action,
				    uint32_t vlan_hdr)
{
	DR_STE_SET(double_action_insert_with_inline_v3, d_action, action_id,
		   DR_STE_V1_ACTION_ID_INSERT_INLINE);
	/* The hardware expects here offset to vlan header in words (2 byte) */
	DR_STE_SET(double_action_insert_with_inline_v3, d_action, start_offset,
		   HDR_LEN_L2_MACS >> 1);
	DR_STE_SET(double_action_insert_with_inline_v3, d_action, inline_data, vlan_hdr);
	dr_ste_v1_set_reparse(ste);
}

static void dr_ste_v3_set_pop_vlan(uint8_t *hw_ste_p, uint8_t *s_action,
				   uint8_t vlans_num)
{
	DR_STE_SET(single_action_remove_header_size_v3, s_action, action_id,
		   DR_STE_V1_ACTION_ID_REMOVE_BY_SIZE);
	DR_STE_SET(single_action_remove_header_size_v3, s_action, start_anchor,
		   DR_STE_HEADER_ANCHOR_1ST_VLAN);
	/* The hardware expects here size in words (2 byte) */
	DR_STE_SET(single_action_remove_header_size_v3, s_action, remove_size,
		   (HDR_LEN_L2_VLAN >> 1) * vlans_num);

	dr_ste_v1_set_reparse(hw_ste_p);
}

static void dr_ste_v3_set_encap_l3(uint8_t *hw_ste_p,
				   uint8_t *frst_s_action,
				   uint8_t *scnd_d_action,
				   uint32_t reformat_id,
				   int size)
{
	/* Remove L2 headers */
	DR_STE_SET(single_action_remove_header_v3, frst_s_action, action_id,
		   DR_STE_V1_ACTION_ID_REMOVE_HEADER_TO_HEADER);
	DR_STE_SET(single_action_remove_header_v3, frst_s_action, end_anchor,
		   DR_STE_HEADER_ANCHOR_IPV6_IPV4);

	/* Encapsulate with given reformat ID */
	DR_STE_SET(double_action_insert_with_ptr_v3, scnd_d_action, action_id,
		   DR_STE_V1_ACTION_ID_INSERT_POINTER);
	/* The hardware expects here size in words (2 bytes) */
	DR_STE_SET(double_action_insert_with_ptr_v3, scnd_d_action, size, size / 2);
	DR_STE_SET(double_action_insert_with_ptr_v3, scnd_d_action, pointer, reformat_id);
	DR_STE_SET(double_action_insert_with_ptr_v3, scnd_d_action, attributes,
		   DR_STE_V1_ACTION_INSERT_PTR_ATTR_ENCAP);

	dr_ste_v1_set_reparse(hw_ste_p);
}

static void dr_ste_v3_set_rx_decap(uint8_t *hw_ste_p, uint8_t *s_action)
{
	DR_STE_SET(single_action_remove_header_v3, s_action, action_id,
		   DR_STE_V1_ACTION_ID_REMOVE_HEADER_TO_HEADER);
	DR_STE_SET(single_action_remove_header_v3, s_action, decap, 1);
	DR_STE_SET(single_action_remove_header_v3, s_action, vni_to_cqe, 1);
	DR_STE_SET(single_action_remove_header_v3, s_action, end_anchor,
		   DR_STE_HEADER_ANCHOR_INNER_MAC);

	dr_ste_v1_set_reparse(hw_ste_p);
}

static int
dr_ste_v3_set_action_decap_l3_list(void *data, uint32_t data_sz,
				   uint8_t *hw_action, uint32_t hw_action_sz,
				   uint16_t *used_hw_action_num)
{
	uint8_t padded_data[DR_STE_L2_HDR_MAX_SZ] = {};
	void *data_ptr = padded_data;
	uint16_t used_actions = 0;
	uint32_t inline_data_sz;
	uint32_t i;

	if (hw_action_sz / DR_STE_ACTION_DOUBLE_SZ < DR_STE_DECAP_L3_ACTION_NUM) {
		errno = EINVAL;
		return errno;
	}

	inline_data_sz =
		DEVX_FLD_SZ_BYTES(ste_double_action_insert_with_inline_v3, inline_data);

	/* Add an alignment padding  */
	memcpy(padded_data + data_sz % inline_data_sz, data, data_sz);

	/* Remove L2L3 outer headers */
	DR_STE_SET(single_action_remove_header_v3, hw_action, action_id,
		   DR_STE_V1_ACTION_ID_REMOVE_HEADER_TO_HEADER);
	DR_STE_SET(single_action_remove_header_v3, hw_action, decap, 1);
	DR_STE_SET(single_action_remove_header_v3, hw_action, vni_to_cqe, 1);
	DR_STE_SET(single_action_remove_header_v3, hw_action, end_anchor,
		   DR_STE_HEADER_ANCHOR_INNER_IPV6_IPV4);
	hw_action += DR_STE_ACTION_DOUBLE_SZ;
	used_actions++;

	/* Point to the last dword of the header */
	data_ptr += (data_sz / inline_data_sz) * inline_data_sz;

	/* Add the new header using inline action 4Byte at a time, the header
	 * is added in reversed order to the beginning of the packet to avoid
	 * incorrect parsing by the HW. Since header is 14B or 18B an extra
	 * two bytes are padded and later removed.
	 */
	for (i = 0; i < data_sz / inline_data_sz + 1; i++) {
		void *addr_inline;

		DR_STE_SET(double_action_insert_with_inline_v3, hw_action, action_id,
			   DR_STE_V1_ACTION_ID_INSERT_INLINE);
		/* The hardware expects here offset to words (2 bytes) */
		DR_STE_SET(double_action_insert_with_inline_v3, hw_action, start_offset, 0);

		/* Copy byte in order to skip endianness problem */
		addr_inline = DEVX_ADDR_OF(ste_double_action_insert_with_inline_v3,
					   hw_action, inline_data);
		memcpy(addr_inline, data_ptr - inline_data_sz * i, inline_data_sz);
		hw_action += DR_STE_ACTION_DOUBLE_SZ;
		used_actions++;
	}

	/* Remove first 2 extra bytes */
	DR_STE_SET(single_action_remove_header_size_v3, hw_action, action_id,
		   DR_STE_V1_ACTION_ID_REMOVE_BY_SIZE);
	DR_STE_SET(single_action_remove_header_size_v3, hw_action, start_offset, 0);
	/* The hardware expects here size in words (2 bytes) */
	DR_STE_SET(single_action_remove_header_size_v3, hw_action, remove_size, 1);
	used_actions++;

	*used_hw_action_num = used_actions;

	return 0;
}

static struct dr_ste_ctx ste_ctx_v3;
static pthread_mutex_t ctx_mutex = PTHREAD_MUTEX_INITIALIZER;

struct dr_ste_ctx *dr_ste_get_ctx_v3(void)
{
	pthread_mutex_lock(&ctx_mutex);

	if (!ste_ctx_v3.actions_caps) {
		ste_ctx_v3 = *dr_ste_get_ctx_v2();
		ste_ctx_v3.set_encap = &dr_ste_v3_set_encap;
		ste_ctx_v3.set_push_vlan = &dr_ste_v3_set_push_vlan;
		ste_ctx_v3.set_pop_vlan = &dr_ste_v3_set_pop_vlan;
		ste_ctx_v3.set_rx_decap = &dr_ste_v3_set_rx_decap;
		ste_ctx_v3.set_encap_l3 = &dr_ste_v3_set_encap_l3;
		ste_ctx_v3.set_action_decap_l3_list = &dr_ste_v3_set_action_decap_l3_list;
	}

	pthread_mutex_unlock(&ctx_mutex);

	return &ste_ctx_v3;
}
