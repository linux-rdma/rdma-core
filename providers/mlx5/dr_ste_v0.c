/*
 * Copyright (c) 2020, Mellanox Technologies. All rights reserved.
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

enum dr_ste_v0_entry_type {
	DR_STE_TYPE_TX		= 1,
	DR_STE_TYPE_RX		= 2,
	DR_STE_TYPE_MODIFY_PKT	= 6,
};

enum dr_ste_v0_action_tunl {
	DR_STE_TUNL_ACTION_NONE		= 0,
	DR_STE_TUNL_ACTION_ENABLE	= 1,
	DR_STE_TUNL_ACTION_DECAP	= 2,
	DR_STE_TUNL_ACTION_L3_DECAP	= 3,
	DR_STE_TUNL_ACTION_POP_VLAN	= 4,
};

enum dr_ste_v0_action_type {
	DR_STE_ACTION_TYPE_PUSH_VLAN    = 1,
	DR_STE_ACTION_TYPE_ENCAP_L3	= 3,
	DR_STE_ACTION_TYPE_ENCAP	= 4,
};

enum dr_ste_v0_action_mdfy_op {
	DR_STE_ACTION_MDFY_OP_COPY	= 0x1,
	DR_STE_ACTION_MDFY_OP_SET	= 0x2,
	DR_STE_ACTION_MDFY_OP_ADD	= 0x3,
};

#define DR_STE_CALC_LU_TYPE(lookup_type, rx, inner) \
	((inner) ? DR_STE_V0_LU_TYPE_##lookup_type##_I : \
		   (rx) ? DR_STE_V0_LU_TYPE_##lookup_type##_D : \
			  DR_STE_V0_LU_TYPE_##lookup_type##_O)

enum dr_ste_v0_lu_type {
	DR_STE_V0_LU_TYPE_NOP				= 0x00,
	DR_STE_V0_LU_TYPE_SRC_GVMI_AND_QP		= 0x05,
	DR_STE_V0_LU_TYPE_ETHL2_TUNNELING_I		= 0x0a,
	DR_STE_V0_LU_TYPE_ETHL2_DST_O			= 0x06,
	DR_STE_V0_LU_TYPE_ETHL2_DST_I			= 0x07,
	DR_STE_V0_LU_TYPE_ETHL2_DST_D			= 0x1b,
	DR_STE_V0_LU_TYPE_ETHL2_SRC_O			= 0x08,
	DR_STE_V0_LU_TYPE_ETHL2_SRC_I			= 0x09,
	DR_STE_V0_LU_TYPE_ETHL2_SRC_D			= 0x1c,
	DR_STE_V0_LU_TYPE_ETHL2_SRC_DST_O		= 0x36,
	DR_STE_V0_LU_TYPE_ETHL2_SRC_DST_I		= 0x37,
	DR_STE_V0_LU_TYPE_ETHL2_SRC_DST_D		= 0x38,
	DR_STE_V0_LU_TYPE_ETHL3_IPV6_DST_O		= 0x0d,
	DR_STE_V0_LU_TYPE_ETHL3_IPV6_DST_I		= 0x0e,
	DR_STE_V0_LU_TYPE_ETHL3_IPV6_DST_D		= 0x1e,
	DR_STE_V0_LU_TYPE_ETHL3_IPV6_SRC_O		= 0x0f,
	DR_STE_V0_LU_TYPE_ETHL3_IPV6_SRC_I		= 0x10,
	DR_STE_V0_LU_TYPE_ETHL3_IPV6_SRC_D		= 0x1f,
	DR_STE_V0_LU_TYPE_ETHL3_IPV4_5_TUPLE_O		= 0x11,
	DR_STE_V0_LU_TYPE_ETHL3_IPV4_5_TUPLE_I		= 0x12,
	DR_STE_V0_LU_TYPE_ETHL3_IPV4_5_TUPLE_D		= 0x20,
	DR_STE_V0_LU_TYPE_ETHL3_IPV4_MISC_O		= 0x29,
	DR_STE_V0_LU_TYPE_ETHL3_IPV4_MISC_I		= 0x2a,
	DR_STE_V0_LU_TYPE_ETHL3_IPV4_MISC_D		= 0x2b,
	DR_STE_V0_LU_TYPE_ETHL4_O			= 0x13,
	DR_STE_V0_LU_TYPE_ETHL4_I			= 0x14,
	DR_STE_V0_LU_TYPE_ETHL4_D			= 0x21,
	DR_STE_V0_LU_TYPE_ETHL4_MISC_O			= 0x2c,
	DR_STE_V0_LU_TYPE_ETHL4_MISC_I			= 0x2d,
	DR_STE_V0_LU_TYPE_ETHL4_MISC_D			= 0x2e,
	DR_STE_V0_LU_TYPE_MPLS_FIRST_O			= 0x15,
	DR_STE_V0_LU_TYPE_MPLS_FIRST_I			= 0x24,
	DR_STE_V0_LU_TYPE_MPLS_FIRST_D			= 0x25,
	DR_STE_V0_LU_TYPE_GRE				= 0x16,
	DR_STE_V0_LU_TYPE_FLEX_PARSER_0			= 0x22,
	DR_STE_V0_LU_TYPE_FLEX_PARSER_1			= 0x23,
	DR_STE_V0_LU_TYPE_FLEX_PARSER_TNL_HEADER	= 0x19,
	DR_STE_V0_LU_TYPE_GENERAL_PURPOSE		= 0x18,
	DR_STE_V0_LU_TYPE_STEERING_REGISTERS_0		= 0x2f,
	DR_STE_V0_LU_TYPE_STEERING_REGISTERS_1		= 0x30,
	DR_STE_V0_LU_TYPE_TUNNEL_HEADER			= 0x34,
	DR_STE_V0_LU_TYPE_DONT_CARE			= DR_STE_LU_TYPE_DONT_CARE,
};

enum {
	DR_STE_V0_ACTION_MDFY_FLD_L2_0		= 0x00,
	DR_STE_V0_ACTION_MDFY_FLD_L2_1		= 0x01,
	DR_STE_V0_ACTION_MDFY_FLD_L2_2		= 0x02,
	DR_STE_V0_ACTION_MDFY_FLD_L3_0		= 0x03,
	DR_STE_V0_ACTION_MDFY_FLD_L3_1		= 0x04,
	DR_STE_V0_ACTION_MDFY_FLD_L3_2		= 0x05,
	DR_STE_V0_ACTION_MDFY_FLD_L3_3		= 0x06,
	DR_STE_V0_ACTION_MDFY_FLD_L3_4		= 0x07,
	DR_STE_V0_ACTION_MDFY_FLD_L4_0		= 0x08,
	DR_STE_V0_ACTION_MDFY_FLD_L4_1		= 0x09,
	DR_STE_V0_ACTION_MDFY_FLD_MPLS		= 0x0a,
	DR_STE_V0_ACTION_MDFY_FLD_L2_TNL_0	= 0x0b,
	DR_STE_V0_ACTION_MDFY_FLD_REG_0		= 0x0c,
	DR_STE_V0_ACTION_MDFY_FLD_REG_1		= 0x0d,
	DR_STE_V0_ACTION_MDFY_FLD_REG_2		= 0x0e,
	DR_STE_V0_ACTION_MDFY_FLD_REG_3		= 0x0f,
	DR_STE_V0_ACTION_MDFY_FLD_L4_2		= 0x10,
	DR_STE_V0_ACTION_MDFY_FLD_FLEX_0	= 0x11,
	DR_STE_V0_ACTION_MDFY_FLD_FLEX_1	= 0x12,
	DR_STE_V0_ACTION_MDFY_FLD_FLEX_2	= 0x13,
	DR_STE_V0_ACTION_MDFY_FLD_FLEX_3	= 0x14,
	DR_STE_V0_ACTION_MDFY_FLD_L2_TNL_1	= 0x15,
	DR_STE_V0_ACTION_MDFY_FLD_METADATA	= 0x16,
	DR_STE_V0_ACTION_MDFY_FLD_RESERVED	= 0x17,
};

static const struct dr_ste_action_modify_field dr_ste_v0_action_modify_field_arr[] = {
	[MLX5_ACTION_IN_FIELD_OUT_SMAC_47_16] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L2_1, .start = 16, .end = 47,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SMAC_15_0] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L2_1, .start = 0, .end = 15,
	},
	[MLX5_ACTION_IN_FIELD_OUT_ETHERTYPE] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L2_2, .start = 32, .end = 47,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DMAC_47_16] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L2_0, .start = 16, .end = 47,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DMAC_15_0] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L2_0, .start = 0, .end = 15,
	},
	[MLX5_ACTION_IN_FIELD_OUT_IP_DSCP] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L3_1, .start = 0, .end = 5,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_FLAGS] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L4_0, .start = 48, .end = 56,
		.l4_type = DR_STE_ACTION_MDFY_TYPE_L4_TCP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_SPORT] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L4_0, .start = 0, .end = 15,
		.l4_type = DR_STE_ACTION_MDFY_TYPE_L4_TCP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_DPORT] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L4_0, .start = 16, .end = 31,
		.l4_type = DR_STE_ACTION_MDFY_TYPE_L4_TCP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_IP_TTL] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L3_1, .start = 8, .end = 15,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV4,
	},
	[MLX5_ACTION_IN_FIELD_OUT_IPV6_HOPLIMIT] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L3_1, .start = 8, .end = 15,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_UDP_SPORT] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L4_0, .start = 0, .end = 15,
		.l4_type = DR_STE_ACTION_MDFY_TYPE_L4_UDP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_UDP_DPORT] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L4_0, .start = 16, .end = 31,
		.l4_type = DR_STE_ACTION_MDFY_TYPE_L4_UDP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV6_127_96] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L3_3, .start = 32, .end = 63,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV6_95_64] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L3_3, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV6_63_32] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L3_4, .start = 32, .end = 63,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV6_31_0] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L3_4, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV6_127_96] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L3_0, .start = 32, .end = 63,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV6_95_64] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L3_0, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV6_63_32] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L3_2, .start = 32, .end = 63,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV6_31_0] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L3_2, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV4] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L3_0, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV4,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV4] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L3_0, .start = 32, .end = 63,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV4,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGA] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_METADATA, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGB] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_METADATA, .start = 32, .end = 63,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_0] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_REG_0, .start = 32, .end = 63,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_1] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_REG_0, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_2] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_REG_1, .start = 32, .end = 63,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_3] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_REG_1, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_4] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_REG_2, .start = 32, .end = 63,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_5] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_REG_2, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_SEQ_NUM] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L4_1, .start = 32, .end = 63,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_ACK_NUM] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L4_1, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_FIRST_VID] = {
		.hw_field = DR_STE_V0_ACTION_MDFY_FLD_L2_2, .start = 0, .end = 15,
	},
};

static void dr_ste_v0_set_entry_type(uint8_t *hw_ste_p, uint8_t entry_type)
{
	DR_STE_SET(general, hw_ste_p, entry_type, entry_type);
}

static uint8_t dr_ste_v0_get_entry_type(uint8_t *hw_ste_p)
{
	return DR_STE_GET(general, hw_ste_p, entry_type);
}

static void dr_ste_v0_set_hit_gvmi(uint8_t *hw_ste_p, uint16_t gvmi)
{
	DR_STE_SET(general, hw_ste_p, next_table_base_63_48, gvmi);
}

static void dr_ste_v0_set_miss_addr(uint8_t *hw_ste_p, uint64_t miss_addr)
{
	uint64_t index = miss_addr >> 6;

	/* Miss address for TX and RX STEs located in the same offsets */
	DR_STE_SET(rx_steering_mult, hw_ste_p, miss_address_39_32, index >> 26);
	DR_STE_SET(rx_steering_mult, hw_ste_p, miss_address_31_6, index);
}

static uint64_t dr_ste_v0_get_miss_addr(uint8_t *hw_ste_p)
{
	uint64_t index =
		(DR_STE_GET(rx_steering_mult, hw_ste_p, miss_address_31_6) |
		 DR_STE_GET(rx_steering_mult, hw_ste_p, miss_address_39_32) << 26);

	return index << 6;
}

static void dr_ste_v0_set_byte_mask(uint8_t *hw_ste_p, uint16_t byte_mask)
{
	DR_STE_SET(general, hw_ste_p, byte_mask, byte_mask);
}

static uint16_t dr_ste_v0_get_byte_mask(uint8_t *hw_ste_p)
{
	return DR_STE_GET(general, hw_ste_p, byte_mask);
}

static void dr_ste_v0_set_lu_type(uint8_t *hw_ste_p, uint16_t lu_type)
{
	DR_STE_SET(general, hw_ste_p, entry_sub_type, lu_type);
}

static void dr_ste_v0_set_next_lu_type(uint8_t *hw_ste_p, uint16_t lu_type)
{
	DR_STE_SET(general, hw_ste_p, next_lu_type, lu_type);
}

static uint16_t dr_ste_v0_get_next_lu_type(uint8_t *hw_ste_p)
{
	return DR_STE_GET(general, hw_ste_p, next_lu_type);
}

static void dr_ste_v0_set_hit_addr(uint8_t *hw_ste_p, uint64_t icm_addr, uint32_t ht_size)
{
	uint64_t index = (icm_addr >> 5) | ht_size;

	DR_STE_SET(general, hw_ste_p, next_table_base_39_32_size, index >> 27);
	DR_STE_SET(general, hw_ste_p, next_table_base_31_5_size, index);
}

static void dr_ste_v0_init_full(uint8_t *hw_ste_p, uint16_t lu_type,
				enum dr_ste_v0_entry_type entry_type,
				uint16_t gvmi)
{
	dr_ste_v0_set_entry_type(hw_ste_p, entry_type);
	dr_ste_v0_set_lu_type(hw_ste_p, lu_type);
	dr_ste_v0_set_next_lu_type(hw_ste_p, DR_STE_LU_TYPE_DONT_CARE);

	DR_STE_SET(rx_steering_mult, hw_ste_p, gvmi, gvmi);
	DR_STE_SET(rx_steering_mult, hw_ste_p, next_table_base_63_48, gvmi);
	DR_STE_SET(rx_steering_mult, hw_ste_p, miss_address_63_48, gvmi);
}

static void dr_ste_v0_init(uint8_t *hw_ste_p, uint16_t lu_type,
			   bool is_rx, uint16_t gvmi)
{
	enum dr_ste_v0_entry_type entry_type;

	entry_type = is_rx ? DR_STE_TYPE_RX : DR_STE_TYPE_TX;

	dr_ste_v0_init_full(hw_ste_p, lu_type, entry_type, gvmi);
}

static void dr_ste_v0_set_ctrl_always_hit_htbl(uint8_t *hw_ste_p,
					       uint16_t byte_mask,
					       uint16_t lu_type,
					       uint64_t icm_addr,
					       uint32_t num_of_entries,
					       uint16_t gvmi)
{
	dr_ste_v0_set_next_lu_type(hw_ste_p, lu_type);
	dr_ste_v0_set_hit_addr(hw_ste_p, icm_addr, num_of_entries);
	dr_ste_v0_set_byte_mask(hw_ste_p, byte_mask);
}

static void dr_ste_v0_set_ctrl_always_miss(uint8_t *hw_ste_p, uint64_t miss_addr,
					   uint16_t gvmi)
{
	dr_ste_v0_set_next_lu_type(hw_ste_p, DR_STE_LU_TYPE_DONT_CARE);
	dr_ste_v0_set_miss_addr(hw_ste_p, miss_addr);
}

static void dr_ste_v0_set_rx_flow_tag(uint8_t *hw_ste_p, uint32_t flow_tag)
{
	DR_STE_SET(rx_steering_mult, hw_ste_p, qp_list_pointer,
		   DR_STE_ENABLE_FLOW_TAG | flow_tag);
}

static void dr_ste_v0_set_counter_id(uint8_t *hw_ste_p, uint32_t ctr_id)
{
	/* This can be used for both rx_steering_mult and for sx_transmit */
	DR_STE_SET(rx_steering_mult, hw_ste_p, counter_trigger_15_0, ctr_id);
	DR_STE_SET(rx_steering_mult, hw_ste_p, counter_trigger_23_16, ctr_id >> 16);
}

static void dr_ste_v0_set_tx_encap(void *hw_ste_p, uint32_t reformat_id,
				   int size, bool encap_l3)
{
	DR_STE_SET(sx_transmit, hw_ste_p, action_type,
		   encap_l3 ? DR_STE_ACTION_TYPE_ENCAP_L3 : DR_STE_ACTION_TYPE_ENCAP);
	/* The hardware expects here size in words (2 byte) */
	DR_STE_SET(sx_transmit, hw_ste_p, action_description, size / 2);
	DR_STE_SET(sx_transmit, hw_ste_p, encap_pointer_vlan_data, reformat_id);
}

static void dr_ste_v0_set_rx_decap(uint8_t *hw_ste_p)
{
	DR_STE_SET(rx_steering_mult, hw_ste_p, tunneling_action,
		   DR_STE_TUNL_ACTION_DECAP);
	DR_STE_SET(rx_steering_mult, hw_ste_p, fail_on_error, 1);
}

static void dr_ste_v0_set_go_back_bit(uint8_t *hw_ste_p)
{
	DR_STE_SET(sx_transmit, hw_ste_p, go_back, 1);
}

static void dr_ste_v0_set_tx_push_vlan(uint8_t *hw_ste_p,
				       uint32_t vlan_hdr,
				       bool go_back)
{
	DR_STE_SET(sx_transmit, hw_ste_p, action_type,
		   DR_STE_ACTION_TYPE_PUSH_VLAN);
	DR_STE_SET(sx_transmit, hw_ste_p, encap_pointer_vlan_data, vlan_hdr);
	/* Due to HW limitation we need to set this bit, otherwise reformat +
	 * push vlan will not work.
	 */
	if (go_back)
		dr_ste_v0_set_go_back_bit(hw_ste_p);
}

static void dr_ste_v0_set_rx_pop_vlan(uint8_t *hw_ste_p)
{
	DR_STE_SET(rx_steering_mult, hw_ste_p, tunneling_action,
		   DR_STE_TUNL_ACTION_POP_VLAN);
}

static void dr_ste_v0_set_rx_decap_l3(uint8_t *hw_ste_p, bool vlan)
{
	DR_STE_SET(rx_steering_mult, hw_ste_p, tunneling_action,
		   DR_STE_TUNL_ACTION_L3_DECAP);
	DR_STE_SET(modify_packet, hw_ste_p, action_description, vlan ? 1 : 0);
	DR_STE_SET(rx_steering_mult, hw_ste_p, fail_on_error, 1);
}

static void dr_ste_v0_set_rewrite_actions(uint8_t *hw_ste_p,
					  uint16_t num_of_actions,
					  uint32_t re_write_index)
{
	DR_STE_SET(modify_packet, hw_ste_p, number_of_re_write_actions,
		   num_of_actions);
	DR_STE_SET(modify_packet, hw_ste_p, header_re_write_actions_pointer,
		   re_write_index);
}

static inline void dr_ste_v0_arr_init_next(uint8_t **last_ste,
					   uint32_t *added_stes,
					   enum dr_ste_v0_entry_type entry_type,
					   uint16_t gvmi)
{
	(*added_stes)++;
	*last_ste += DR_STE_SIZE;
	dr_ste_v0_init_full(*last_ste, DR_STE_LU_TYPE_DONT_CARE, entry_type, gvmi);
}

static void dr_ste_v0_set_actions_tx(uint8_t *action_type_set,
				     uint8_t *last_ste,
				     struct dr_ste_actions_attr *attr,
				     uint32_t *added_stes)
{
	bool encap = action_type_set[DR_ACTION_TYP_L2_TO_TNL_L2] ||
		action_type_set[DR_ACTION_TYP_L2_TO_TNL_L3];

	/* We want to make sure the modify header comes before L2
	 * encapsulation. The reason for that is that we support
	 * modify headers for outer headers only
	 */
	if (action_type_set[DR_ACTION_TYP_MODIFY_HDR]) {
		dr_ste_v0_set_entry_type(last_ste, DR_STE_TYPE_MODIFY_PKT);
		dr_ste_v0_set_rewrite_actions(last_ste,
					      attr->modify_actions,
					      attr->modify_index);
	}

	if (action_type_set[DR_ACTION_TYP_PUSH_VLAN]) {
		int i;

		for (i = 0; i < attr->vlans.count; i++) {
			if (i || action_type_set[DR_ACTION_TYP_MODIFY_HDR])
				dr_ste_v0_arr_init_next(&last_ste,
							added_stes,
							DR_STE_TYPE_TX,
							attr->gvmi);

			dr_ste_v0_set_tx_push_vlan(last_ste,
						   attr->vlans.headers[i],
						   encap);
		}
	}

	if (encap) {
		/* Modify header and encapsulation require a different STEs.
		 * Since modify header STE format doesn't support encapsulation
		 * tunneling_action. Encapsulation and push VLAN cannot be set
		 * on the same STE.
		 */
		if (action_type_set[DR_ACTION_TYP_MODIFY_HDR] ||
		    action_type_set[DR_ACTION_TYP_PUSH_VLAN])
			dr_ste_v0_arr_init_next(&last_ste,
						added_stes,
						DR_STE_TYPE_TX,
						attr->gvmi);

		dr_ste_v0_set_tx_encap(last_ste,
				       attr->reformat_id,
				       attr->reformat_size,
				       action_type_set[DR_ACTION_TYP_L2_TO_TNL_L3]);
		/* Whenever prio_tag_required enabled, we can be sure that the
		 * previous table (ACL) already push vlan to our packet,
		 * And due to HW limitation we need to set this bit, otherwise
		 * push vlan + reformat will not work.
		 */
		if (attr->prio_tag_required)
			dr_ste_v0_set_go_back_bit(last_ste);
	}

	if (action_type_set[DR_ACTION_TYP_CTR])
		dr_ste_v0_set_counter_id(last_ste, attr->ctr_id);

	dr_ste_v0_set_hit_gvmi(last_ste, attr->hit_gvmi);
	dr_ste_v0_set_hit_addr(last_ste, attr->final_icm_addr, 1);
}

static void dr_ste_v0_set_actions_rx(uint8_t *action_type_set,
				     uint8_t *last_ste,
				     struct dr_ste_actions_attr *attr,
				     uint32_t *added_stes)
{
	if (action_type_set[DR_ACTION_TYP_CTR])
		dr_ste_v0_set_counter_id(last_ste, attr->ctr_id);

	if (action_type_set[DR_ACTION_TYP_TNL_L3_TO_L2]) {
		dr_ste_v0_set_entry_type(last_ste, DR_STE_TYPE_MODIFY_PKT);
		dr_ste_v0_set_rx_decap_l3(last_ste, attr->decap_with_vlan);
		dr_ste_v0_set_rewrite_actions(last_ste,
					      attr->decap_actions,
					      attr->decap_index);
	}

	if (action_type_set[DR_ACTION_TYP_TNL_L2_TO_L2])
		dr_ste_v0_set_rx_decap(last_ste);

	if (action_type_set[DR_ACTION_TYP_POP_VLAN]) {
		int i;

		for (i = 0; i < attr->vlans.count; i++) {
			if (i ||
			    action_type_set[DR_ACTION_TYP_TNL_L2_TO_L2] ||
			    action_type_set[DR_ACTION_TYP_TNL_L3_TO_L2])
				dr_ste_v0_arr_init_next(&last_ste,
							added_stes,
							DR_STE_TYPE_RX,
							attr->gvmi);

			dr_ste_v0_set_rx_pop_vlan(last_ste);
		}
	}

	if (action_type_set[DR_ACTION_TYP_MODIFY_HDR]) {
		if (dr_ste_v0_get_entry_type(last_ste) == DR_STE_TYPE_MODIFY_PKT)
			dr_ste_v0_arr_init_next(&last_ste,
						added_stes,
						DR_STE_TYPE_MODIFY_PKT,
						attr->gvmi);
		else
			dr_ste_v0_set_entry_type(last_ste, DR_STE_TYPE_MODIFY_PKT);

		dr_ste_v0_set_rewrite_actions(last_ste,
					      attr->modify_actions,
					      attr->modify_index);
	}

	if (action_type_set[DR_ACTION_TYP_TAG]) {
		if (dr_ste_v0_get_entry_type(last_ste) == DR_STE_TYPE_MODIFY_PKT)
			dr_ste_v0_arr_init_next(&last_ste,
						added_stes,
						DR_STE_TYPE_RX,
						attr->gvmi);

		dr_ste_v0_set_rx_flow_tag(last_ste, attr->flow_tag);
	}

	dr_ste_v0_set_hit_gvmi(last_ste, attr->hit_gvmi);
	dr_ste_v0_set_hit_addr(last_ste, attr->final_icm_addr, 1);
}

static void dr_ste_v0_set_action_set(uint8_t *hw_action,
				     uint8_t hw_field,
				     uint8_t shifter,
				     uint8_t length,
				     uint32_t data)
{
	length = (length == 32) ? 0 : length;
	DEVX_SET(dr_action_hw_set, hw_action, opcode, DR_STE_ACTION_MDFY_OP_SET);
	DEVX_SET(dr_action_hw_set, hw_action, destination_field_code, hw_field);
	DEVX_SET(dr_action_hw_set, hw_action, destination_left_shifter, shifter);
	DEVX_SET(dr_action_hw_set, hw_action, destination_length, length);
	DEVX_SET(dr_action_hw_set, hw_action, inline_data, data);
}

static void dr_ste_v0_set_action_add(uint8_t *hw_action,
				     uint8_t hw_field,
				     uint8_t shifter,
				     uint8_t length,
				     uint32_t data)
{
	length = (length == 32) ? 0 : length;
	DEVX_SET(dr_action_hw_set, hw_action, opcode, DR_STE_ACTION_MDFY_OP_ADD);
	DEVX_SET(dr_action_hw_set, hw_action, destination_field_code, hw_field);
	DEVX_SET(dr_action_hw_set, hw_action, destination_left_shifter, shifter);
	DEVX_SET(dr_action_hw_set, hw_action, destination_length, length);
	DEVX_SET(dr_action_hw_set, hw_action, inline_data, data);
}

static void dr_ste_v0_set_action_copy(uint8_t *hw_action,
				      uint8_t dst_hw_field,
				      uint8_t dst_shifter,
				      uint8_t dst_len,
				      uint8_t src_hw_field,
				      uint8_t src_shifter)
{
	DEVX_SET(dr_action_hw_copy, hw_action, opcode, DR_STE_ACTION_MDFY_OP_COPY);
	DEVX_SET(dr_action_hw_copy, hw_action, destination_field_code, dst_hw_field);
	DEVX_SET(dr_action_hw_copy, hw_action, destination_left_shifter, dst_shifter);
	DEVX_SET(dr_action_hw_copy, hw_action, destination_length, dst_len);
	DEVX_SET(dr_action_hw_copy, hw_action, source_field_code, src_hw_field);
	DEVX_SET(dr_action_hw_copy, hw_action, source_left_shifter, src_shifter);
}

#define DR_STE_DECAP_L3_MIN_ACTION_NUM	5

static int
dr_ste_v0_set_action_decap_l3_list(void *data, uint32_t data_sz,
				   uint8_t *hw_action, uint32_t hw_action_sz,
				   uint16_t *used_hw_action_num)
{
	struct mlx5_ifc_l2_hdr_bits *l2_hdr = data;
	uint32_t hw_action_num;
	int required_actions;
	uint32_t hdr_fld_4b;
	uint16_t hdr_fld_2b;
	uint16_t vlan_type;
	bool vlan;

	vlan = (data_sz != HDR_LEN_L2);
	hw_action_num = hw_action_sz / DEVX_ST_SZ_BYTES(dr_action_hw_set);
	required_actions = DR_STE_DECAP_L3_MIN_ACTION_NUM + !!vlan;

	if (hw_action_num < required_actions) {
		errno = ENOMEM;
		return errno;
	}

	/* dmac_47_16 */
	DEVX_SET(dr_action_hw_set, hw_action, opcode, DR_STE_ACTION_MDFY_OP_SET);
	DEVX_SET(dr_action_hw_set, hw_action, destination_length, 0);
	DEVX_SET(dr_action_hw_set, hw_action, destination_field_code, DR_STE_V0_ACTION_MDFY_FLD_L2_0);
	DEVX_SET(dr_action_hw_set, hw_action, destination_left_shifter, 16);
	hdr_fld_4b = DEVX_GET(l2_hdr, l2_hdr, dmac_47_16);
	DEVX_SET(dr_action_hw_set, hw_action, inline_data, hdr_fld_4b);
	hw_action += DEVX_ST_SZ_BYTES(dr_action_hw_set);

	/* smac_47_16 */
	DEVX_SET(dr_action_hw_set, hw_action, opcode, DR_STE_ACTION_MDFY_OP_SET);
	DEVX_SET(dr_action_hw_set, hw_action, destination_length, 0);
	DEVX_SET(dr_action_hw_set, hw_action, destination_field_code, DR_STE_V0_ACTION_MDFY_FLD_L2_1);
	DEVX_SET(dr_action_hw_set, hw_action, destination_left_shifter, 16);
	hdr_fld_4b = (DEVX_GET(l2_hdr, l2_hdr, smac_31_0) >> 16 |
		      DEVX_GET(l2_hdr, l2_hdr, smac_47_32) << 16);
	DEVX_SET(dr_action_hw_set, hw_action, inline_data, hdr_fld_4b);
	hw_action += DEVX_ST_SZ_BYTES(dr_action_hw_set);

	/* dmac_15_0 */
	DEVX_SET(dr_action_hw_set, hw_action, opcode, DR_STE_ACTION_MDFY_OP_SET);
	DEVX_SET(dr_action_hw_set, hw_action, destination_length, 16);
	DEVX_SET(dr_action_hw_set, hw_action, destination_field_code, DR_STE_V0_ACTION_MDFY_FLD_L2_0);
	DEVX_SET(dr_action_hw_set, hw_action, destination_left_shifter, 0);
	hdr_fld_2b = DEVX_GET(l2_hdr, l2_hdr, dmac_15_0);
	DEVX_SET(dr_action_hw_set, hw_action, inline_data, hdr_fld_2b);
	hw_action += DEVX_ST_SZ_BYTES(dr_action_hw_set);

	/* ethertype + (optional) vlan */
	DEVX_SET(dr_action_hw_set, hw_action, opcode, DR_STE_ACTION_MDFY_OP_SET);
	DEVX_SET(dr_action_hw_set, hw_action, destination_field_code, DR_STE_V0_ACTION_MDFY_FLD_L2_2);
	DEVX_SET(dr_action_hw_set, hw_action, destination_left_shifter, 32);
	if (!vlan) {
		hdr_fld_2b = DEVX_GET(l2_hdr, l2_hdr, ethertype);
		DEVX_SET(dr_action_hw_set, hw_action, inline_data, hdr_fld_2b);
		DEVX_SET(dr_action_hw_set, hw_action, destination_length, 16);
	} else {
		hdr_fld_2b = DEVX_GET(l2_hdr, l2_hdr, ethertype);
		vlan_type = hdr_fld_2b == SVLAN_ETHERTYPE ? DR_STE_SVLAN : DR_STE_CVLAN;
		hdr_fld_2b = DEVX_GET(l2_hdr, l2_hdr, vlan);
		hdr_fld_4b = (vlan_type << 16) | hdr_fld_2b;
		DEVX_SET(dr_action_hw_set, hw_action, inline_data, hdr_fld_4b);
		DEVX_SET(dr_action_hw_set, hw_action, destination_length, 18);
	}
	hw_action += DEVX_ST_SZ_BYTES(dr_action_hw_set);

	/* smac_15_0 */
	DEVX_SET(dr_action_hw_set, hw_action, opcode, DR_STE_ACTION_MDFY_OP_SET);
	DEVX_SET(dr_action_hw_set, hw_action, destination_length, 16);
	DEVX_SET(dr_action_hw_set, hw_action, destination_field_code, DR_STE_V0_ACTION_MDFY_FLD_L2_1);
	DEVX_SET(dr_action_hw_set, hw_action, destination_left_shifter, 0);
	hdr_fld_2b = DEVX_GET(l2_hdr, l2_hdr, smac_31_0);
	DEVX_SET(dr_action_hw_set, hw_action, inline_data, hdr_fld_2b);
	hw_action += DEVX_ST_SZ_BYTES(dr_action_hw_set);

	if (vlan) {
		DEVX_SET(dr_action_hw_set, hw_action, opcode, DR_STE_ACTION_MDFY_OP_SET);
		hdr_fld_2b = DEVX_GET(l2_hdr, l2_hdr, vlan_type);
		DEVX_SET(dr_action_hw_set, hw_action, inline_data, hdr_fld_2b);
		DEVX_SET(dr_action_hw_set, hw_action, destination_length, 16);
		DEVX_SET(dr_action_hw_set, hw_action, destination_field_code, DR_STE_V0_ACTION_MDFY_FLD_L2_2);
		DEVX_SET(dr_action_hw_set, hw_action, destination_left_shifter, 0);
	}

	*used_hw_action_num = required_actions;

	return 0;
}

static const struct dr_ste_action_modify_field
*dr_ste_v0_get_action_hw_field(uint16_t sw_field, struct dr_devx_caps *caps)
{
	const struct dr_ste_action_modify_field *hw_field;

	if (sw_field >= ARRAY_SIZE(dr_ste_v0_action_modify_field_arr))
		goto not_found;

	hw_field = &dr_ste_v0_action_modify_field_arr[sw_field];
	if (!hw_field->end && !hw_field->start)
		goto not_found;

	return hw_field;

not_found:
	errno = EINVAL;
	return NULL;
}

static void dr_ste_v0_build_eth_l2_src_dst_bit_mask(struct dr_match_param *value,
						    bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l2_src_dst, bit_mask, dmac_47_16, mask, dmac_47_16);
	DR_STE_SET_TAG(eth_l2_src_dst, bit_mask, dmac_15_0, mask, dmac_15_0);

	if (mask->smac_47_16 || mask->smac_15_0) {
		DR_STE_SET(eth_l2_src_dst, bit_mask, smac_47_32,
			   mask->smac_47_16 >> 16);
		DR_STE_SET(eth_l2_src_dst, bit_mask, smac_31_0,
			   mask->smac_47_16 << 16 | mask->smac_15_0);
		mask->smac_47_16 = 0;
		mask->smac_15_0 = 0;
	}

	DR_STE_SET_TAG(eth_l2_src_dst, bit_mask, first_vlan_id, mask, first_vid);
	DR_STE_SET_TAG(eth_l2_src_dst, bit_mask, first_cfi, mask, first_cfi);
	DR_STE_SET_TAG(eth_l2_src_dst, bit_mask, first_priority, mask, first_prio);
	DR_STE_SET_ONES(eth_l2_src_dst, bit_mask, l3_type, mask, ip_version);

	if (mask->cvlan_tag) {
		DR_STE_SET(eth_l2_src_dst, bit_mask, first_vlan_qualifier, -1);
		mask->cvlan_tag = 0;
	} else if (mask->svlan_tag) {
		DR_STE_SET(eth_l2_src_dst, bit_mask, first_vlan_qualifier, -1);
		mask->svlan_tag = 0;
	}
}

static int dr_ste_v0_build_eth_l2_src_dst_tag(struct dr_match_param *value,
					      struct dr_ste_build *sb,
					      uint8_t *tag)
{
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;

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

static void dr_ste_v0_build_eth_l2_src_dst_init(struct dr_ste_build *sb,
						struct dr_match_param *mask)
{
	dr_ste_v0_build_eth_l2_src_dst_bit_mask(mask, sb->inner, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL2_SRC_DST, sb->rx, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_eth_l2_src_dst_tag;
}

static int dr_ste_v0_build_eth_l3_ipv6_dst_tag(struct dr_match_param *value,
					       struct dr_ste_build *sb,
					       uint8_t *tag)
{
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l3_ipv6_dst, tag, dst_ip_127_96, spec, dst_ip_127_96);
	DR_STE_SET_TAG(eth_l3_ipv6_dst, tag, dst_ip_95_64, spec, dst_ip_95_64);
	DR_STE_SET_TAG(eth_l3_ipv6_dst, tag, dst_ip_63_32, spec, dst_ip_63_32);
	DR_STE_SET_TAG(eth_l3_ipv6_dst, tag, dst_ip_31_0, spec, dst_ip_31_0);

	return 0;
}

static void dr_ste_v0_build_eth_l3_ipv6_dst_init(struct dr_ste_build *sb,
						 struct dr_match_param *mask)
{
	dr_ste_v0_build_eth_l3_ipv6_dst_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL3_IPV6_DST, sb->rx, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_eth_l3_ipv6_dst_tag;
}

static int dr_ste_v0_build_eth_l3_ipv6_src_tag(struct dr_match_param *value,
					       struct dr_ste_build *sb,
					       uint8_t *tag)
{
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l3_ipv6_src, tag, src_ip_127_96, spec, src_ip_127_96);
	DR_STE_SET_TAG(eth_l3_ipv6_src, tag, src_ip_95_64, spec, src_ip_95_64);
	DR_STE_SET_TAG(eth_l3_ipv6_src, tag, src_ip_63_32, spec, src_ip_63_32);
	DR_STE_SET_TAG(eth_l3_ipv6_src, tag, src_ip_31_0, spec, src_ip_31_0);

	return 0;
}

static void dr_ste_v0_build_eth_l3_ipv6_src_init(struct dr_ste_build *sb,
						 struct dr_match_param *mask)
{
	dr_ste_v0_build_eth_l3_ipv6_src_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL3_IPV6_SRC, sb->rx, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_eth_l3_ipv6_src_tag;
}

static int dr_ste_v0_build_eth_l3_ipv4_5_tuple_tag(struct dr_match_param *value,
						   struct dr_ste_build *sb,
						   uint8_t *tag)
{
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;

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

static void dr_ste_v0_build_eth_l3_ipv4_5_tuple_init(struct dr_ste_build *sb,
						     struct dr_match_param *mask)
{
	dr_ste_v0_build_eth_l3_ipv4_5_tuple_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL3_IPV4_5_TUPLE, sb->rx, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_eth_l3_ipv4_5_tuple_tag;
}

static void dr_ste_v0_build_eth_l2_src_or_dst_bit_mask(struct dr_match_param *value,
						       bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;
	struct dr_match_misc *misc_mask = &value->misc;

	DR_STE_SET_TAG(eth_l2_src, bit_mask, first_vlan_id, mask, first_vid);
	DR_STE_SET_TAG(eth_l2_src, bit_mask, first_cfi, mask, first_cfi);
	DR_STE_SET_TAG(eth_l2_src, bit_mask, first_priority, mask, first_prio);
	DR_STE_SET_TAG(eth_l2_src, bit_mask, ip_fragmented, mask, frag);
	DR_STE_SET_TAG(eth_l2_src, bit_mask, l3_ethertype, mask, ethertype);
	DR_STE_SET_ONES(eth_l2_src, bit_mask, l3_type, mask, ip_version);

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

		DR_STE_SET_TAG(eth_l2_src, bit_mask, second_vlan_id, misc_mask, inner_second_vid);
		DR_STE_SET_TAG(eth_l2_src, bit_mask, second_cfi, misc_mask, inner_second_cfi);
		DR_STE_SET_TAG(eth_l2_src, bit_mask, second_priority, misc_mask, inner_second_prio);
	} else {
		if (misc_mask->outer_second_cvlan_tag ||
		    misc_mask->outer_second_svlan_tag) {
			DR_STE_SET(eth_l2_src, bit_mask, second_vlan_qualifier, -1);
			misc_mask->outer_second_cvlan_tag = 0;
			misc_mask->outer_second_svlan_tag = 0;
		}

		DR_STE_SET_TAG(eth_l2_src, bit_mask, second_vlan_id, misc_mask, outer_second_vid);
		DR_STE_SET_TAG(eth_l2_src, bit_mask, second_cfi, misc_mask, outer_second_cfi);
		DR_STE_SET_TAG(eth_l2_src, bit_mask, second_priority, misc_mask, outer_second_prio);
	}
}

static int dr_ste_v0_build_eth_l2_src_or_dst_tag(struct dr_match_param *value,
						 bool inner, uint8_t *tag)
{
	struct dr_match_spec *spec = inner ? &value->inner : &value->outer;
	struct dr_match_misc *misc_spec = &value->misc;

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

static void dr_ste_v0_build_eth_l2_src_bit_mask(struct dr_match_param *value,
						bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l2_src, bit_mask, smac_47_16, mask, smac_47_16);
	DR_STE_SET_TAG(eth_l2_src, bit_mask, smac_15_0, mask, smac_15_0);

	dr_ste_v0_build_eth_l2_src_or_dst_bit_mask(value, inner, bit_mask);
}

static int dr_ste_v0_build_eth_l2_src_tag(struct dr_match_param *value,
					  struct dr_ste_build *sb,
					  uint8_t *tag)
{
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l2_src, tag, smac_47_16, spec, smac_47_16);
	DR_STE_SET_TAG(eth_l2_src, tag, smac_15_0, spec, smac_15_0);

	return dr_ste_v0_build_eth_l2_src_or_dst_tag(value, sb->inner, tag);
}

static void dr_ste_v0_build_eth_l2_src_init(struct dr_ste_build *sb,
					    struct dr_match_param *mask)
{
	dr_ste_v0_build_eth_l2_src_bit_mask(mask, sb->inner, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL2_SRC, sb->rx, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_eth_l2_src_tag;
}

static void dr_ste_v0_build_eth_l2_dst_bit_mask(struct dr_match_param *value,
						struct dr_ste_build *sb,
						uint8_t *bit_mask)
{
	struct dr_match_spec *mask = sb->inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l2_dst, bit_mask, dmac_47_16, mask, dmac_47_16);
	DR_STE_SET_TAG(eth_l2_dst, bit_mask, dmac_15_0, mask, dmac_15_0);

	dr_ste_v0_build_eth_l2_src_or_dst_bit_mask(value, sb->inner, bit_mask);
}

static int dr_ste_v0_build_eth_l2_dst_tag(struct dr_match_param *value,
					  struct dr_ste_build *sb,
					  uint8_t *tag)
{
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l2_dst, tag, dmac_47_16, spec, dmac_47_16);
	DR_STE_SET_TAG(eth_l2_dst, tag, dmac_15_0, spec, dmac_15_0);

	return dr_ste_v0_build_eth_l2_src_or_dst_tag(value, sb->inner, tag);
}

static void dr_ste_v0_build_eth_l2_dst_init(struct dr_ste_build *sb,
					    struct dr_match_param *mask)
{
	dr_ste_v0_build_eth_l2_dst_bit_mask(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL2_DST, sb->rx, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_eth_l2_dst_tag;
}

static void dr_ste_v0_build_eth_l2_tnl_bit_mask(struct dr_match_param *value,
						bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;
	struct dr_match_misc *misc = &value->misc;

	DR_STE_SET_TAG(eth_l2_tnl, bit_mask, dmac_47_16, mask, dmac_47_16);
	DR_STE_SET_TAG(eth_l2_tnl, bit_mask, dmac_15_0, mask, dmac_15_0);
	DR_STE_SET_TAG(eth_l2_tnl, bit_mask, first_vlan_id, mask, first_vid);
	DR_STE_SET_TAG(eth_l2_tnl, bit_mask, first_cfi, mask, first_cfi);
	DR_STE_SET_TAG(eth_l2_tnl, bit_mask, first_priority, mask, first_prio);
	DR_STE_SET_TAG(eth_l2_tnl, bit_mask, ip_fragmented, mask, frag);
	DR_STE_SET_TAG(eth_l2_tnl, bit_mask, l3_ethertype, mask, ethertype);
	DR_STE_SET_ONES(eth_l2_tnl, bit_mask, l3_type, mask, ip_version);

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

static int dr_ste_v0_build_eth_l2_tnl_tag(struct dr_match_param *value,
					  struct dr_ste_build *sb,
					  uint8_t *tag)
{
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;
	struct dr_match_misc *misc = &value->misc;

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

static void dr_ste_v0_build_eth_l2_tnl_init(struct dr_ste_build *sb,
					    struct dr_match_param *mask)
{
	dr_ste_v0_build_eth_l2_tnl_bit_mask(mask, sb->inner, sb->bit_mask);

	sb->lu_type = DR_STE_V0_LU_TYPE_ETHL2_TUNNELING_I;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_eth_l2_tnl_tag;
}

static int dr_ste_v0_build_eth_l3_ipv4_misc_tag(struct dr_match_param *value,
						struct dr_ste_build *sb,
						uint8_t *tag)
{
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l3_ipv4_misc, tag, time_to_live, spec, ip_ttl_hoplimit);
	DR_STE_SET_TAG(eth_l3_ipv4_misc, tag, ihl, spec, ipv4_ihl);

	return 0;
}

static void dr_ste_v0_build_eth_l3_ipv4_misc_init(struct dr_ste_build *sb,
						  struct dr_match_param *mask)
{
	dr_ste_v0_build_eth_l3_ipv4_misc_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL3_IPV4_MISC, sb->rx, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_eth_l3_ipv4_misc_tag;
}

static int dr_ste_v0_build_eth_ipv6_l3_l4_tag(struct dr_match_param *value,
					      struct dr_ste_build *sb,
					      uint8_t *tag)
{
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;
	struct dr_match_misc *misc = &value->misc;

	DR_STE_SET_TAG(eth_l4, tag, dst_port, spec, tcp_dport);
	DR_STE_SET_TAG(eth_l4, tag, src_port, spec, tcp_sport);
	DR_STE_SET_TAG(eth_l4, tag, dst_port, spec, udp_dport);
	DR_STE_SET_TAG(eth_l4, tag, src_port, spec, udp_sport);
	DR_STE_SET_TAG(eth_l4, tag, protocol, spec, ip_protocol);
	DR_STE_SET_TAG(eth_l4, tag, fragmented, spec, frag);
	DR_STE_SET_TAG(eth_l4, tag, dscp, spec, ip_dscp);
	DR_STE_SET_TAG(eth_l4, tag, ecn, spec, ip_ecn);
	DR_STE_SET_TAG(eth_l4, tag, ipv6_hop_limit, spec, ip_ttl_hoplimit);

	if (sb->inner)
		DR_STE_SET_TAG(eth_l4, tag, flow_label, misc, inner_ipv6_flow_label);
	else
		DR_STE_SET_TAG(eth_l4, tag, flow_label, misc, outer_ipv6_flow_label);

	if (spec->tcp_flags) {
		DR_STE_SET_TCP_FLAGS(eth_l4, tag, spec);
		spec->tcp_flags = 0;
	}

	return 0;
}

static void dr_ste_v0_build_eth_ipv6_l3_l4_init(struct dr_ste_build *sb,
						struct dr_match_param *mask)
{
	dr_ste_v0_build_eth_ipv6_l3_l4_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL4, sb->rx, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_eth_ipv6_l3_l4_tag;
}

static int dr_ste_v0_build_mpls_tag(struct dr_match_param *value,
				    struct dr_ste_build *sb,
				    uint8_t *tag)
{
	struct dr_match_misc2 *misc2 = &value->misc2;

	if (sb->inner)
		DR_STE_SET_MPLS(mpls, misc2, inner, tag);
	else
		DR_STE_SET_MPLS(mpls, misc2, outer, tag);

	return 0;
}

static void dr_ste_v0_build_mpls_init(struct dr_ste_build *sb,
				      struct dr_match_param *mask)
{
	dr_ste_v0_build_mpls_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_LU_TYPE(MPLS_FIRST, sb->rx, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_mpls_tag;
}

static int dr_ste_v0_build_tnl_gre_tag(struct dr_match_param *value,
				       struct dr_ste_build *sb,
				       uint8_t *tag)
{
	struct  dr_match_misc *misc = &value->misc;

	DR_STE_SET_TAG(gre, tag, gre_protocol, misc, gre_protocol);
	DR_STE_SET_TAG(gre, tag, gre_k_present, misc, gre_k_present);
	DR_STE_SET_TAG(gre, tag, gre_key_h, misc, gre_key_h);
	DR_STE_SET_TAG(gre, tag, gre_key_l, misc, gre_key_l);

	DR_STE_SET_TAG(gre, tag, gre_c_present, misc, gre_c_present);
	DR_STE_SET_TAG(gre, tag, gre_s_present, misc, gre_s_present);

	return 0;
}

static void dr_ste_v0_build_tnl_gre_init(struct dr_ste_build *sb,
					 struct dr_match_param *mask)
{
	dr_ste_v0_build_tnl_gre_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V0_LU_TYPE_GRE;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_tnl_gre_tag;
}

static int dr_ste_v0_build_tnl_mpls_over_udp_tag(struct dr_match_param *value,
						 struct dr_ste_build *sb,
						 uint8_t *tag)
{
	struct dr_match_misc2 *misc2 = &value->misc2;
	uint8_t *parser_ptr;
	uint8_t parser_id;
	uint32_t mpls_hdr;

	mpls_hdr = misc2->outer_first_mpls_over_udp_label << HDR_MPLS_OFFSET_LABEL;
	misc2->outer_first_mpls_over_udp_label = 0;
	mpls_hdr |= misc2->outer_first_mpls_over_udp_exp << HDR_MPLS_OFFSET_EXP;
	misc2->outer_first_mpls_over_udp_exp = 0;
	mpls_hdr |= misc2->outer_first_mpls_over_udp_s_bos << HDR_MPLS_OFFSET_S_BOS;
	misc2->outer_first_mpls_over_udp_s_bos = 0;
	mpls_hdr |= misc2->outer_first_mpls_over_udp_ttl << HDR_MPLS_OFFSET_TTL;
	misc2->outer_first_mpls_over_udp_ttl = 0;

	parser_id = sb->caps->flex_parser_id_mpls_over_udp;
	parser_ptr = dr_ste_calc_flex_parser_offset(tag, parser_id);
	*(__be32 *)parser_ptr = htobe32(mpls_hdr);

	return 0;
}

static void dr_ste_v0_build_tnl_mpls_over_udp_init(struct dr_ste_build *sb,
						   struct dr_match_param *mask)
{
	dr_ste_v0_build_tnl_mpls_over_udp_tag(mask, sb, sb->bit_mask);

	/* STEs with lookup type FLEX_PARSER_{0/1} includes
	 * flex parsers_{0-3}/{4-7} respectively.
	 */
	sb->lu_type = sb->caps->flex_parser_id_mpls_over_udp <= DR_STE_MAX_FLEX_0_ID ?
		      DR_STE_V0_LU_TYPE_FLEX_PARSER_0 :
		      DR_STE_V0_LU_TYPE_FLEX_PARSER_1;

	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_tnl_mpls_over_udp_tag;
}

static int dr_ste_v0_build_tnl_mpls_over_gre_tag(struct dr_match_param *value,
						 struct dr_ste_build *sb,
						 uint8_t *tag)
{
	struct dr_match_misc2 *misc2 = &value->misc2;
	uint8_t *parser_ptr;
	uint8_t parser_id;
	uint32_t mpls_hdr;

	mpls_hdr = misc2->outer_first_mpls_over_gre_label << HDR_MPLS_OFFSET_LABEL;
	misc2->outer_first_mpls_over_gre_label = 0;
	mpls_hdr |= misc2->outer_first_mpls_over_gre_exp << HDR_MPLS_OFFSET_EXP;
	misc2->outer_first_mpls_over_gre_exp = 0;
	mpls_hdr |= misc2->outer_first_mpls_over_gre_s_bos << HDR_MPLS_OFFSET_S_BOS;
	misc2->outer_first_mpls_over_gre_s_bos = 0;
	mpls_hdr |= misc2->outer_first_mpls_over_gre_ttl << HDR_MPLS_OFFSET_TTL;
	misc2->outer_first_mpls_over_gre_ttl = 0;

	parser_id = sb->caps->flex_parser_id_mpls_over_gre;
	parser_ptr = dr_ste_calc_flex_parser_offset(tag, parser_id);
	*(__be32 *)parser_ptr = htobe32(mpls_hdr);

	return 0;
}

static void dr_ste_v0_build_tnl_mpls_over_gre_init(struct dr_ste_build *sb,
						   struct dr_match_param *mask)
{
	dr_ste_v0_build_tnl_mpls_over_gre_tag(mask, sb, sb->bit_mask);

	/* STEs with lookup type FLEX_PARSER_{0/1} includes
	 * flex parsers_{0-3}/{4-7} respectively.
	 */
	sb->lu_type = sb->caps->flex_parser_id_mpls_over_gre <= DR_STE_MAX_FLEX_0_ID ?
		      DR_STE_V0_LU_TYPE_FLEX_PARSER_0 :
		      DR_STE_V0_LU_TYPE_FLEX_PARSER_1;

	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_tnl_mpls_over_gre_tag;
}

#define ICMP_TYPE_OFFSET_FIRST_DW	24
#define ICMP_CODE_OFFSET_FIRST_DW	16

static int dr_ste_v0_build_icmp_tag(struct dr_match_param *value,
				    struct dr_ste_build *sb,
				    uint8_t *tag)
{
	struct dr_match_misc3 *misc3 = &value->misc3;
	bool is_ipv4 = DR_MASK_IS_ICMPV4_SET(misc3);
	uint32_t *icmp_header_data;
	uint8_t *parser_ptr;
	uint8_t *icmp_type;
	uint8_t *icmp_code;
	uint32_t icmp_hdr;
	int dw0_location;
	int dw1_location;

	if (is_ipv4) {
		icmp_header_data	= &misc3->icmpv4_header_data;
		icmp_type		= &misc3->icmpv4_type;
		icmp_code		= &misc3->icmpv4_code;
		dw0_location		= sb->caps->flex_parser_id_icmp_dw0;
		dw1_location		= sb->caps->flex_parser_id_icmp_dw1;
	} else {
		icmp_header_data	= &misc3->icmpv6_header_data;
		icmp_type		= &misc3->icmpv6_type;
		icmp_code		= &misc3->icmpv6_code;
		dw0_location		= sb->caps->flex_parser_id_icmpv6_dw0;
		dw1_location		= sb->caps->flex_parser_id_icmpv6_dw1;
	}

	parser_ptr = dr_ste_calc_flex_parser_offset(tag, dw0_location);
	icmp_hdr = (*icmp_type << ICMP_TYPE_OFFSET_FIRST_DW) |
		   (*icmp_code << ICMP_CODE_OFFSET_FIRST_DW);
	*(__be32 *)parser_ptr = htobe32(icmp_hdr);
	*icmp_code = 0;
	*icmp_type = 0;

	parser_ptr = dr_ste_calc_flex_parser_offset(tag, dw1_location);
	*(__be32 *)parser_ptr = htobe32(*icmp_header_data);
	*icmp_header_data = 0;

	return 0;
}

static void dr_ste_v0_build_icmp_init(struct dr_ste_build *sb,
				      struct dr_match_param *mask)
{
	uint8_t parser_id;
	bool is_ipv4;

	dr_ste_v0_build_icmp_tag(mask, sb, sb->bit_mask);

	/* STEs with lookup type FLEX_PARSER_{0/1} includes
	 * flex parsers_{0-3}/{4-7} respectively.
	 */
	is_ipv4 = DR_MASK_IS_ICMPV4_SET(&mask->misc3);
	parser_id = is_ipv4 ? sb->caps->flex_parser_id_icmp_dw0 :
			      sb->caps->flex_parser_id_icmpv6_dw0;
	sb->lu_type = parser_id <= DR_STE_MAX_FLEX_0_ID ?
		      DR_STE_V0_LU_TYPE_FLEX_PARSER_0 :
		      DR_STE_V0_LU_TYPE_FLEX_PARSER_1;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_icmp_tag;
}

static int dr_ste_v0_build_general_purpose_tag(struct dr_match_param *value,
					       struct dr_ste_build *sb,
					       uint8_t *tag)
{
	struct dr_match_misc2 *misc2 = &value->misc2;

	DR_STE_SET_TAG(general_purpose, tag, general_purpose_lookup_field,
		       misc2, metadata_reg_a);

	return 0;
}

static void dr_ste_v0_build_general_purpose_init(struct dr_ste_build *sb,
						 struct dr_match_param *mask)
{
	dr_ste_v0_build_general_purpose_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V0_LU_TYPE_GENERAL_PURPOSE;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_general_purpose_tag;
}

static int dr_ste_v0_build_eth_l4_misc_tag(struct dr_match_param *value,
					   struct dr_ste_build *sb,
					   uint8_t *tag)
{
	struct dr_match_misc3 *misc3 = &value->misc3;

	if (sb->inner) {
		DR_STE_SET_TAG(eth_l4_misc, tag, seq_num, misc3, inner_tcp_seq_num);
		DR_STE_SET_TAG(eth_l4_misc, tag, ack_num, misc3, inner_tcp_ack_num);
	} else {
		DR_STE_SET_TAG(eth_l4_misc, tag, seq_num, misc3, outer_tcp_seq_num);
		DR_STE_SET_TAG(eth_l4_misc, tag, ack_num, misc3, outer_tcp_ack_num);
	}

	return 0;
}

static void dr_ste_v0_build_eth_l4_misc_init(struct dr_ste_build *sb,
					     struct dr_match_param *mask)
{
	dr_ste_v0_build_eth_l4_misc_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL4_MISC, sb->rx, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_eth_l4_misc_tag;
}

static int
dr_ste_v0_build_flex_parser_tnl_vxlan_gpe_tag(struct dr_match_param *value,
					      struct dr_ste_build *sb,
					      uint8_t *tag)
{
	struct dr_match_misc3 *misc3 = &value->misc3;

	DR_STE_SET_TAG(flex_parser_tnl_vxlan_gpe, tag,
		       outer_vxlan_gpe_flags, misc3,
		       outer_vxlan_gpe_flags);
	DR_STE_SET_TAG(flex_parser_tnl_vxlan_gpe, tag,
		       outer_vxlan_gpe_next_protocol, misc3,
		       outer_vxlan_gpe_next_protocol);
	DR_STE_SET_TAG(flex_parser_tnl_vxlan_gpe, tag,
		       outer_vxlan_gpe_vni, misc3,
		       outer_vxlan_gpe_vni);

	return 0;
}

static void
dr_ste_v0_build_flex_parser_tnl_vxlan_gpe_init(struct dr_ste_build *sb,
					       struct dr_match_param *mask)
{
	dr_ste_v0_build_flex_parser_tnl_vxlan_gpe_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V0_LU_TYPE_FLEX_PARSER_TNL_HEADER;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_flex_parser_tnl_vxlan_gpe_tag;
}

static int
dr_ste_v0_build_flex_parser_tnl_geneve_tag(struct dr_match_param *value,
					   struct dr_ste_build *sb,
					   uint8_t *tag)
{
	struct dr_match_misc *misc = &value->misc;

	DR_STE_SET_TAG(flex_parser_tnl_geneve, tag,
		       geneve_protocol_type, misc, geneve_protocol_type);
	DR_STE_SET_TAG(flex_parser_tnl_geneve, tag,
		       geneve_oam, misc, geneve_oam);
	DR_STE_SET_TAG(flex_parser_tnl_geneve, tag,
		       geneve_opt_len, misc, geneve_opt_len);
	DR_STE_SET_TAG(flex_parser_tnl_geneve, tag,
		       geneve_vni, misc, geneve_vni);

	return 0;
}

static void
dr_ste_v0_build_flex_parser_tnl_geneve_init(struct dr_ste_build *sb,
					    struct dr_match_param *mask)
{
	dr_ste_v0_build_flex_parser_tnl_geneve_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V0_LU_TYPE_FLEX_PARSER_TNL_HEADER;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_flex_parser_tnl_geneve_tag;
}

static int
dr_ste_v0_build_flex_parser_tnl_geneve_tlv_opt_tag(struct dr_match_param *value,
						   struct dr_ste_build *sb,
						   uint8_t *tag)
{
	uint8_t parser_id = sb->caps->flex_parser_id_geneve_opt_0;
	uint8_t *parser_ptr = dr_ste_calc_flex_parser_offset(tag, parser_id);
	struct dr_match_misc3 *misc3 = &value->misc3;

	*(__be32 *)parser_ptr = htobe32(misc3->geneve_tlv_option_0_data);
	misc3->geneve_tlv_option_0_data = 0;

	return 0;
}

static void
dr_ste_v0_build_flex_parser_tnl_geneve_tlv_opt_init(struct dr_ste_build *sb,
						    struct dr_match_param *mask)
{
	dr_ste_v0_build_flex_parser_tnl_geneve_tlv_opt_tag(mask, sb, sb->bit_mask);

	/* STEs with lookup type FLEX_PARSER_{0/1} includes
	 * flex parsers_{0-3}/{4-7} respectively.
	 */
	sb->lu_type = sb->caps->flex_parser_id_geneve_opt_0 <= DR_STE_MAX_FLEX_0_ID ?
		      DR_STE_V0_LU_TYPE_FLEX_PARSER_0 :
		      DR_STE_V0_LU_TYPE_FLEX_PARSER_1;

	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_flex_parser_tnl_geneve_tlv_opt_tag;
}

static int dr_ste_v0_build_flex_parser_tnl_gtpu_tag(struct dr_match_param *value,
						    struct dr_ste_build *sb,
						    uint8_t *tag)
{
	struct dr_match_misc3 *misc3 = &value->misc3;

	DR_STE_SET_TAG(flex_parser_tnl_gtpu, tag,
		       gtpu_msg_flags, misc3,
		       gtpu_msg_flags);
	DR_STE_SET_TAG(flex_parser_tnl_gtpu, tag,
		       gtpu_msg_type, misc3,
		       gtpu_msg_type);
	DR_STE_SET_TAG(flex_parser_tnl_gtpu, tag,
		       gtpu_teid, misc3,
		       gtpu_teid);

	return 0;
}

static void dr_ste_v0_build_flex_parser_tnl_gtpu_init(struct dr_ste_build *sb,
						      struct dr_match_param *mask)
{
	dr_ste_v0_build_flex_parser_tnl_gtpu_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V0_LU_TYPE_FLEX_PARSER_TNL_HEADER;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_flex_parser_tnl_gtpu_tag;
}

static int
dr_ste_v0_build_tnl_gtpu_flex_parser_0_tag(struct dr_match_param *value,
					   struct dr_ste_build *sb,
					   uint8_t *tag)
{
	if (sb->caps->flex_parser_id_gtpu_dw_0 <= DR_STE_MAX_FLEX_0_ID)
		DR_STE_SET_FLEX_PARSER_FIELD(tag, gtpu_dw_0, sb->caps, &value->misc3);
	if (sb->caps->flex_parser_id_gtpu_teid <= DR_STE_MAX_FLEX_0_ID)
		DR_STE_SET_FLEX_PARSER_FIELD(tag, gtpu_teid, sb->caps, &value->misc3);
	if (sb->caps->flex_parser_id_gtpu_dw_2 <= DR_STE_MAX_FLEX_0_ID)
		DR_STE_SET_FLEX_PARSER_FIELD(tag, gtpu_dw_2, sb->caps, &value->misc3);
	if (sb->caps->flex_parser_id_gtpu_first_ext_dw_0 <= DR_STE_MAX_FLEX_0_ID)
		DR_STE_SET_FLEX_PARSER_FIELD(tag, gtpu_first_ext_dw_0, sb->caps, &value->misc3);
	return 0;
}

static void
dr_ste_v0_build_tnl_gtpu_flex_parser_0_init(struct dr_ste_build *sb,
					    struct dr_match_param *mask)
{
	dr_ste_v0_build_tnl_gtpu_flex_parser_0_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V0_LU_TYPE_FLEX_PARSER_0;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_tnl_gtpu_flex_parser_0_tag;
}

static int
dr_ste_v0_build_tnl_gtpu_flex_parser_1_tag(struct dr_match_param *value,
					   struct dr_ste_build *sb,
					   uint8_t *tag)
{
	if (sb->caps->flex_parser_id_gtpu_dw_0 > DR_STE_MAX_FLEX_0_ID)
		DR_STE_SET_FLEX_PARSER_FIELD(tag, gtpu_dw_0, sb->caps, &value->misc3);
	if (sb->caps->flex_parser_id_gtpu_teid > DR_STE_MAX_FLEX_0_ID)
		DR_STE_SET_FLEX_PARSER_FIELD(tag, gtpu_teid, sb->caps, &value->misc3);
	if (sb->caps->flex_parser_id_gtpu_dw_2 > DR_STE_MAX_FLEX_0_ID)
		DR_STE_SET_FLEX_PARSER_FIELD(tag, gtpu_dw_2, sb->caps, &value->misc3);
	if (sb->caps->flex_parser_id_gtpu_first_ext_dw_0 > DR_STE_MAX_FLEX_0_ID)
		DR_STE_SET_FLEX_PARSER_FIELD(tag, gtpu_first_ext_dw_0, sb->caps, &value->misc3);
	return 0;
}

static void
dr_ste_v0_build_tnl_gtpu_flex_parser_1_init(struct dr_ste_build *sb,
					    struct dr_match_param *mask)
{
	dr_ste_v0_build_tnl_gtpu_flex_parser_1_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V0_LU_TYPE_FLEX_PARSER_1;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_tnl_gtpu_flex_parser_1_tag;
}

static int dr_ste_v0_build_register_0_tag(struct dr_match_param *value,
					  struct dr_ste_build *sb,
					  uint8_t *tag)
{
	struct dr_match_misc2 *misc2 = &value->misc2;

	DR_STE_SET_TAG(register_0, tag, register_0_h, misc2, metadata_reg_c_0);
	DR_STE_SET_TAG(register_0, tag, register_0_l, misc2, metadata_reg_c_1);
	DR_STE_SET_TAG(register_0, tag, register_1_h, misc2, metadata_reg_c_2);
	DR_STE_SET_TAG(register_0, tag, register_1_l, misc2, metadata_reg_c_3);

	return 0;
}

static void dr_ste_v0_build_register_0_init(struct dr_ste_build *sb,
					    struct dr_match_param *mask)
{
	dr_ste_v0_build_register_0_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V0_LU_TYPE_STEERING_REGISTERS_0;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_register_0_tag;
}

static int dr_ste_v0_build_register_1_tag(struct dr_match_param *value,
					  struct dr_ste_build *sb,
					  uint8_t *tag)
{
	struct dr_match_misc2 *misc2 = &value->misc2;

	DR_STE_SET_TAG(register_1, tag, register_2_h, misc2, metadata_reg_c_4);
	DR_STE_SET_TAG(register_1, tag, register_2_l, misc2, metadata_reg_c_5);
	DR_STE_SET_TAG(register_1, tag, register_3_h, misc2, metadata_reg_c_6);
	DR_STE_SET_TAG(register_1, tag, register_3_l, misc2, metadata_reg_c_7);

	return 0;
}

static void dr_ste_v0_build_register_1_init(struct dr_ste_build *sb,
					    struct dr_match_param *mask)
{
	dr_ste_v0_build_register_1_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V0_LU_TYPE_STEERING_REGISTERS_1;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_register_1_tag;
}

static void dr_ste_v0_build_src_gvmi_qpn_bit_mask(struct dr_match_param *value,
						  struct dr_ste_build *sb)
{
	struct dr_match_misc *misc_mask = &value->misc;
	uint8_t *bit_mask = sb->bit_mask;

	if (sb->rx && misc_mask->source_port)
		DR_STE_SET(src_gvmi_qp, bit_mask, functional_lb, 1);

	DR_STE_SET_ONES(src_gvmi_qp, bit_mask, source_gvmi, misc_mask, source_port);
	DR_STE_SET_ONES(src_gvmi_qp, bit_mask, source_qp, misc_mask, source_sqn);
}

static int dr_ste_v0_build_src_gvmi_qpn_tag(struct dr_match_param *value,
					    struct dr_ste_build *sb,
					    uint8_t *tag)
{
	struct dr_match_misc *misc = &value->misc;
	struct dr_devx_vport_cap *vport_cap;
	uint8_t *bit_mask = sb->bit_mask;
	bool source_gvmi_set;

	DR_STE_SET_TAG(src_gvmi_qp, tag, source_qp, misc, source_sqn);

	source_gvmi_set = DR_STE_GET(src_gvmi_qp, bit_mask, source_gvmi);
	if (source_gvmi_set) {
		vport_cap = dr_vports_table_get_vport_cap(sb->caps,
							  misc->source_port);
		if (!vport_cap)
			return errno;

		if (vport_cap->vport_gvmi)
			DR_STE_SET(src_gvmi_qp, tag, source_gvmi, vport_cap->vport_gvmi);

		/* Make sure that this packet is not coming from the wire since
		 * wire GVMI is set to 0 and can be aliased with another port
		 */
		if (sb->rx && misc->source_port != WIRE_PORT)
			DR_STE_SET(src_gvmi_qp, tag, functional_lb, 1);

		misc->source_port = 0;
	}

	return 0;
}

static void dr_ste_v0_build_src_gvmi_qpn_init(struct dr_ste_build *sb,
					      struct dr_match_param *mask)
{
	dr_ste_v0_build_src_gvmi_qpn_bit_mask(mask, sb);

	sb->lu_type = DR_STE_V0_LU_TYPE_SRC_GVMI_AND_QP;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_src_gvmi_qpn_tag;
}

static void dr_ste_set_flex_parser(uint16_t lu_type,
				   uint32_t *misc4_field_id,
				   uint32_t *misc4_field_value,
				   bool *parser_is_used,
				   uint8_t *tag)
{
	uint32_t id = *misc4_field_id;
	uint8_t *parser_ptr;
	bool skip_parser;

	/* Since this is a shared function to set flex parsers,
	 * we need to skip it if lookup type and parser ID doesn't match
	 */
	skip_parser = id <= DR_STE_MAX_FLEX_0_ID ?
		      lu_type != DR_STE_V0_LU_TYPE_FLEX_PARSER_0 :
		      lu_type != DR_STE_V0_LU_TYPE_FLEX_PARSER_1;

	skip_parser = skip_parser || (id >= NUM_OF_FLEX_PARSERS);

	if (skip_parser || parser_is_used[id])
		return;

	parser_is_used[id] = true;
	parser_ptr = dr_ste_calc_flex_parser_offset(tag, id);

	*(__be32 *)parser_ptr = htobe32(*misc4_field_value);
	*misc4_field_id = 0;
	*misc4_field_value = 0;
}

static int dr_ste_v0_build_flex_parser_tag(struct dr_match_param *value,
					   struct dr_ste_build *sb,
					   uint8_t *tag)
{
	struct dr_match_misc4 *misc_4_mask = &value->misc4;
	bool parser_is_used[NUM_OF_FLEX_PARSERS] = {};

	dr_ste_set_flex_parser(sb->lu_type,
			       &misc_4_mask->prog_sample_field_id_0,
			       &misc_4_mask->prog_sample_field_value_0,
			       parser_is_used, tag);

	dr_ste_set_flex_parser(sb->lu_type,
			       &misc_4_mask->prog_sample_field_id_1,
			       &misc_4_mask->prog_sample_field_value_1,
			       parser_is_used, tag);

	dr_ste_set_flex_parser(sb->lu_type,
			       &misc_4_mask->prog_sample_field_id_2,
			       &misc_4_mask->prog_sample_field_value_2,
			       parser_is_used, tag);

	dr_ste_set_flex_parser(sb->lu_type,
			       &misc_4_mask->prog_sample_field_id_3,
			       &misc_4_mask->prog_sample_field_value_3,
			       parser_is_used, tag);

	dr_ste_set_flex_parser(sb->lu_type,
			       &misc_4_mask->prog_sample_field_id_4,
			       &misc_4_mask->prog_sample_field_value_4,
			       parser_is_used, tag);

	dr_ste_set_flex_parser(sb->lu_type,
			       &misc_4_mask->prog_sample_field_id_5,
			       &misc_4_mask->prog_sample_field_value_5,
			       parser_is_used, tag);

	dr_ste_set_flex_parser(sb->lu_type,
			       &misc_4_mask->prog_sample_field_id_6,
			       &misc_4_mask->prog_sample_field_value_6,
			       parser_is_used, tag);

	dr_ste_set_flex_parser(sb->lu_type,
			       &misc_4_mask->prog_sample_field_id_7,
			       &misc_4_mask->prog_sample_field_value_7,
			       parser_is_used, tag);
	return 0;
}

static void dr_ste_v0_build_flex_parser_0_init(struct dr_ste_build *sb,
					       struct dr_match_param *mask)
{
	sb->lu_type = DR_STE_V0_LU_TYPE_FLEX_PARSER_0;
	dr_ste_v0_build_flex_parser_tag(mask, sb, sb->bit_mask);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_flex_parser_tag;
}

static void dr_ste_v0_build_flex_parser_1_init(struct dr_ste_build *sb,
					       struct dr_match_param *mask)
{
	sb->lu_type = DR_STE_V0_LU_TYPE_FLEX_PARSER_1;
	dr_ste_v0_build_flex_parser_tag(mask, sb, sb->bit_mask);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_flex_parser_tag;
}

static int dr_ste_v0_build_tunnel_header_0_1_tag(struct dr_match_param *value,
						 struct dr_ste_build *sb,
						 uint8_t *tag)
{
	struct dr_match_misc5 *misc5 = &value->misc5;

	DR_STE_SET_TAG(tunnel_header, tag, tunnel_header_dw0, misc5, tunnel_header_0);
	DR_STE_SET_TAG(tunnel_header, tag, tunnel_header_dw1, misc5, tunnel_header_1);

	return 0;
}

static void dr_ste_v0_build_tunnel_header_0_1_init(struct dr_ste_build *sb,
						   struct dr_match_param *mask)
{
	sb->lu_type = DR_STE_V0_LU_TYPE_TUNNEL_HEADER;
	dr_ste_v0_build_tunnel_header_0_1_tag(mask, sb, sb->bit_mask);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_tunnel_header_0_1_tag;
}

static struct dr_ste_ctx ste_ctx_v0 = {
	/* Builders */
	.build_eth_l2_src_dst_init	= &dr_ste_v0_build_eth_l2_src_dst_init,
	.build_eth_l3_ipv6_src_init	= &dr_ste_v0_build_eth_l3_ipv6_src_init,
	.build_eth_l3_ipv6_dst_init	= &dr_ste_v0_build_eth_l3_ipv6_dst_init,
	.build_eth_l3_ipv4_5_tuple_init	= &dr_ste_v0_build_eth_l3_ipv4_5_tuple_init,
	.build_eth_l2_src_init		= &dr_ste_v0_build_eth_l2_src_init,
	.build_eth_l2_dst_init		= &dr_ste_v0_build_eth_l2_dst_init,
	.build_eth_l2_tnl_init		= &dr_ste_v0_build_eth_l2_tnl_init,
	.build_eth_l3_ipv4_misc_init	= &dr_ste_v0_build_eth_l3_ipv4_misc_init,
	.build_eth_ipv6_l3_l4_init	= &dr_ste_v0_build_eth_ipv6_l3_l4_init,
	.build_mpls_init		= &dr_ste_v0_build_mpls_init,
	.build_tnl_gre_init		= &dr_ste_v0_build_tnl_gre_init,
	.build_tnl_mpls_over_udp_init	= &dr_ste_v0_build_tnl_mpls_over_udp_init,
	.build_tnl_mpls_over_gre_init	= &dr_ste_v0_build_tnl_mpls_over_gre_init,
	.build_icmp_init		= &dr_ste_v0_build_icmp_init,
	.build_general_purpose_init	= &dr_ste_v0_build_general_purpose_init,
	.build_eth_l4_misc_init		= &dr_ste_v0_build_eth_l4_misc_init,
	.build_tnl_vxlan_gpe_init	= &dr_ste_v0_build_flex_parser_tnl_vxlan_gpe_init,
	.build_tnl_geneve_init		= &dr_ste_v0_build_flex_parser_tnl_geneve_init,
	.build_tnl_geneve_tlv_opt_init	= &dr_ste_v0_build_flex_parser_tnl_geneve_tlv_opt_init,
	.build_tnl_gtpu_init		= &dr_ste_v0_build_flex_parser_tnl_gtpu_init,
	.build_tnl_gtpu_flex_parser_0	= &dr_ste_v0_build_tnl_gtpu_flex_parser_0_init,
	.build_tnl_gtpu_flex_parser_1	= &dr_ste_v0_build_tnl_gtpu_flex_parser_1_init,
	.build_register_0_init		= &dr_ste_v0_build_register_0_init,
	.build_register_1_init		= &dr_ste_v0_build_register_1_init,
	.build_src_gvmi_qpn_init	= &dr_ste_v0_build_src_gvmi_qpn_init,
	.build_flex_parser_0_init	= &dr_ste_v0_build_flex_parser_0_init,
	.build_flex_parser_1_init	= &dr_ste_v0_build_flex_parser_1_init,
	.build_tunnel_header_0_1	= &dr_ste_v0_build_tunnel_header_0_1_init,
	/* Getters and Setters */
	.ste_init			= &dr_ste_v0_init,
	.set_next_lu_type		= &dr_ste_v0_set_next_lu_type,
	.get_next_lu_type		= &dr_ste_v0_get_next_lu_type,
	.set_miss_addr			= &dr_ste_v0_set_miss_addr,
	.get_miss_addr			= &dr_ste_v0_get_miss_addr,
	.set_hit_addr			= &dr_ste_v0_set_hit_addr,
	.set_byte_mask			= &dr_ste_v0_set_byte_mask,
	.get_byte_mask			= &dr_ste_v0_get_byte_mask,
	.set_ctrl_always_hit_htbl	= &dr_ste_v0_set_ctrl_always_hit_htbl,
	.set_ctrl_always_miss		= &dr_ste_v0_set_ctrl_always_miss,
	.set_hit_gvmi			= &dr_ste_v0_set_hit_gvmi,
	/* Actions */
	.actions_caps			= DR_STE_CTX_ACTION_CAP_NONE,
	.set_actions_rx			= &dr_ste_v0_set_actions_rx,
	.set_actions_tx			= &dr_ste_v0_set_actions_tx,
	.set_action_set			= &dr_ste_v0_set_action_set,
	.set_action_add			= &dr_ste_v0_set_action_add,
	.set_action_copy		= &dr_ste_v0_set_action_copy,
	.get_action_hw_field		= &dr_ste_v0_get_action_hw_field,
	.set_action_decap_l3_list	= &dr_ste_v0_set_action_decap_l3_list,
};

struct dr_ste_ctx *dr_ste_get_ctx_v0(void)
{
	return &ste_ctx_v0;
}
