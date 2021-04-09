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

#define DR_STE_CALC_DFNR_TYPE(lookup_type, inner) \
	((inner) ? DR_STE_V1_LU_TYPE_##lookup_type##_I : \
		   DR_STE_V1_LU_TYPE_##lookup_type##_O)

enum dr_ste_v1_entry_format {
	DR_STE_V1_TYPE_BWC_BYTE	= 0x0,
	DR_STE_V1_TYPE_BWC_DW	= 0x1,
	DR_STE_V1_TYPE_MATCH	= 0x2,
};

/*
 * Lookup type is built from 2B: [ Definer mode 1B ][ Definer index 1B ]
 */
enum dr_ste_v1_lu_type {
	DR_STE_V1_LU_TYPE_NOP				= 0x0000,
	DR_STE_V1_LU_TYPE_ETHL2_TNL			= 0x0002,
	DR_STE_V1_LU_TYPE_IBL3_EXT			= 0x0102,
	DR_STE_V1_LU_TYPE_ETHL2_O			= 0x0003,
	DR_STE_V1_LU_TYPE_IBL4				= 0x0103,
	DR_STE_V1_LU_TYPE_ETHL2_I			= 0x0004,
	DR_STE_V1_LU_TYPE_SRC_QP_GVMI			= 0x0104,
	DR_STE_V1_LU_TYPE_ETHL2_SRC_O			= 0x0005,
	DR_STE_V1_LU_TYPE_ETHL2_HEADERS_O		= 0x0105,
	DR_STE_V1_LU_TYPE_ETHL2_SRC_I			= 0x0006,
	DR_STE_V1_LU_TYPE_ETHL2_HEADERS_I		= 0x0106,
	DR_STE_V1_LU_TYPE_ETHL3_IPV4_5_TUPLE_O		= 0x0007,
	DR_STE_V1_LU_TYPE_IPV6_DES_O			= 0x0107,
	DR_STE_V1_LU_TYPE_ETHL3_IPV4_5_TUPLE_I		= 0x0008,
	DR_STE_V1_LU_TYPE_IPV6_DES_I			= 0x0108,
	DR_STE_V1_LU_TYPE_ETHL4_O			= 0x0009,
	DR_STE_V1_LU_TYPE_IPV6_SRC_O			= 0x0109,
	DR_STE_V1_LU_TYPE_ETHL4_I			= 0x000a,
	DR_STE_V1_LU_TYPE_IPV6_SRC_I			= 0x010a,
	DR_STE_V1_LU_TYPE_ETHL2_SRC_DST_O		= 0x000b,
	DR_STE_V1_LU_TYPE_MPLS_O			= 0x010b,
	DR_STE_V1_LU_TYPE_ETHL2_SRC_DST_I		= 0x000c,
	DR_STE_V1_LU_TYPE_MPLS_I			= 0x010c,
	DR_STE_V1_LU_TYPE_ETHL3_IPV4_MISC_O		= 0x000d,
	DR_STE_V1_LU_TYPE_GRE				= 0x010d,
	DR_STE_V1_LU_TYPE_FLEX_PARSER_TNL_HEADER	= 0x000e,
	DR_STE_V1_LU_TYPE_GENERAL_PURPOSE		= 0x010e,
	DR_STE_V1_LU_TYPE_ETHL3_IPV4_MISC_I		= 0x000f,
	DR_STE_V1_LU_TYPE_STEERING_REGISTERS_0		= 0x010f,
	DR_STE_V1_LU_TYPE_STEERING_REGISTERS_1		= 0x0110,
	DR_STE_V1_LU_TYPE_FLEX_PARSER_0			= 0x0111,
	DR_STE_V1_LU_TYPE_FLEX_PARSER_1			= 0x0112,
	DR_STE_V1_LU_TYPE_ETHL4_MISC_O			= 0x0113,
	DR_STE_V1_LU_TYPE_ETHL4_MISC_I			= 0x0114,
	DR_STE_V1_LU_TYPE_INVALID			= 0x00ff,
	DR_STE_V1_LU_TYPE_DONT_CARE			= DR_STE_LU_TYPE_DONT_CARE,
};

enum dr_ste_v1_header_anchors {
	DR_STE_HEADER_ANCHOR_START_OUTER		= 0x00,
	DR_STE_HEADER_ANCHOR_1ST_VLAN			= 0x02,
	DR_STE_HEADER_ANCHOR_IPV6_IPV4			= 0x07,
	DR_STE_HEADER_ANCHOR_INNER_MAC			= 0x13,
	DR_STE_HEADER_ANCHOR_INNER_IPV6_IPV4		= 0x19,
};

enum dr_ste_v1_action_size {
	DR_STE_ACTION_SINGLE_SZ = 4,
	DR_STE_ACTION_DOUBLE_SZ = 8,
	DR_STE_ACTION_TRIPLE_SZ = 12,
};

enum dr_ste_v1_action_insert_ptr_attr {
	DR_STE_V1_ACTION_INSERT_PTR_ATTR_NONE = 0,  /* Regular push header (e.g. push vlan) */
	DR_STE_V1_ACTION_INSERT_PTR_ATTR_ENCAP = 1, /* Encapsulation / Tunneling */
	DR_STE_V1_ACTION_INSERT_PTR_ATTR_ESP = 2,   /* IPsec */
};

enum dr_ste_v1_action_id {
	DR_STE_V1_ACTION_ID_NOP				= 0x00,
	DR_STE_V1_ACTION_ID_COPY			= 0x05,
	DR_STE_V1_ACTION_ID_SET				= 0x06,
	DR_STE_V1_ACTION_ID_ADD				= 0x07,
	DR_STE_V1_ACTION_ID_REMOVE_BY_SIZE		= 0x08,
	DR_STE_V1_ACTION_ID_REMOVE_HEADER_TO_HEADER	= 0x09,
	DR_STE_V1_ACTION_ID_INSERT_INLINE		= 0x0a,
	DR_STE_V1_ACTION_ID_INSERT_POINTER		= 0x0b,
	DR_STE_V1_ACTION_ID_FLOW_TAG			= 0x0c,
	DR_STE_V1_ACTION_ID_QUEUE_ID_SEL		= 0x0d,
	DR_STE_V1_ACTION_ID_ACCELERATED_LIST		= 0x0e,
	DR_STE_V1_ACTION_ID_MODIFY_LIST			= 0x0f,
	DR_STE_V1_ACTION_ID_ASO				= 0x12,
	DR_STE_V1_ACTION_ID_TRAILER			= 0x13,
	DR_STE_V1_ACTION_ID_COUNTER_ID			= 0x14,
	DR_STE_V1_ACTION_ID_MAX				= 0x21,
	/* use for special cases */
	DR_STE_V1_ACTION_ID_SPECIAL_ENCAP_L3		= 0x22,
};

enum {
	DR_STE_V1_ACTION_MDFY_FLD_L2_OUT_0		= 0x00,
	DR_STE_V1_ACTION_MDFY_FLD_L2_OUT_1		= 0x01,
	DR_STE_V1_ACTION_MDFY_FLD_L2_OUT_2		= 0x02,
	DR_STE_V1_ACTION_MDFY_FLD_SRC_L2_OUT_0		= 0x08,
	DR_STE_V1_ACTION_MDFY_FLD_SRC_L2_OUT_1		= 0x09,
	DR_STE_V1_ACTION_MDFY_FLD_L3_OUT_0		= 0x0e,
	DR_STE_V1_ACTION_MDFY_FLD_L4_OUT_0		= 0x18,
	DR_STE_V1_ACTION_MDFY_FLD_L4_OUT_1		= 0x19,
	DR_STE_V1_ACTION_MDFY_FLD_IPV4_OUT_0		= 0x40,
	DR_STE_V1_ACTION_MDFY_FLD_IPV4_OUT_1		= 0x41,
	DR_STE_V1_ACTION_MDFY_FLD_IPV6_DST_OUT_0	= 0x44,
	DR_STE_V1_ACTION_MDFY_FLD_IPV6_DST_OUT_1	= 0x45,
	DR_STE_V1_ACTION_MDFY_FLD_IPV6_DST_OUT_2	= 0x46,
	DR_STE_V1_ACTION_MDFY_FLD_IPV6_DST_OUT_3	= 0x47,
	DR_STE_V1_ACTION_MDFY_FLD_IPV6_SRC_OUT_0	= 0x4c,
	DR_STE_V1_ACTION_MDFY_FLD_IPV6_SRC_OUT_1	= 0x4d,
	DR_STE_V1_ACTION_MDFY_FLD_IPV6_SRC_OUT_2	= 0x4e,
	DR_STE_V1_ACTION_MDFY_FLD_IPV6_SRC_OUT_3	= 0x4f,
	DR_STE_V1_ACTION_MDFY_FLD_TCP_MISC_0		= 0x5e,
	DR_STE_V1_ACTION_MDFY_FLD_TCP_MISC_1		= 0x5f,
	DR_STE_V1_ACTION_MDFY_FLD_METADATA_2_CQE	= 0x7b,
	DR_STE_V1_ACTION_MDFY_FLD_GNRL_PURPOSE		= 0x7c,
	DR_STE_V1_ACTION_MDFY_FLD_FLEX_PARSER_7		= 0x82,
	DR_STE_V1_ACTION_MDFY_FLD_FLEX_PARSER_6		= 0x83,
	DR_STE_V1_ACTION_MDFY_FLD_FLEX_PARSER_5		= 0x84,
	DR_STE_V1_ACTION_MDFY_FLD_FLEX_PARSER_4		= 0x85,
	DR_STE_V1_ACTION_MDFY_FLD_FLEX_PARSER_3		= 0x86,
	DR_STE_V1_ACTION_MDFY_FLD_FLEX_PARSER_2		= 0x87,
	DR_STE_V1_ACTION_MDFY_FLD_FLEX_PARSER_1		= 0x88,
	DR_STE_V1_ACTION_MDFY_FLD_FLEX_PARSER_0		= 0x89,
	DR_STE_V1_ACTION_MDFY_FLD_REGISTER_2		= 0x8c,
	DR_STE_V1_ACTION_MDFY_FLD_REGISTER_3		= 0x8d,
	DR_STE_V1_ACTION_MDFY_FLD_REGISTER_4		= 0x8e,
	DR_STE_V1_ACTION_MDFY_FLD_REGISTER_5		= 0x8f,
	DR_STE_V1_ACTION_MDFY_FLD_REGISTER_6		= 0x90,
	DR_STE_V1_ACTION_MDFY_FLD_REGISTER_7		= 0x91,
};

enum dr_ste_v1_aso_ctx_type {
	DR_STE_V1_ASO_CTX_TYPE_CT = 0x1,
	DR_STE_V1_ASO_CTX_TYPE_POLICERS = 0x2,
	DR_STE_V1_ASO_CTX_TYPE_FIRST_HIT = 0x4,
};

static const struct dr_ste_action_modify_field dr_ste_v1_action_modify_field_arr[] = {
	[MLX5_ACTION_IN_FIELD_OUT_SMAC_47_16] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_SRC_L2_OUT_0, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SMAC_15_0] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_SRC_L2_OUT_1, .start = 16, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_ETHERTYPE] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L2_OUT_1, .start = 0, .end = 15,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DMAC_47_16] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L2_OUT_0, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DMAC_15_0] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L2_OUT_1, .start = 16, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_IP_DSCP] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L3_OUT_0, .start = 18, .end = 23,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_FLAGS] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L4_OUT_1, .start = 16, .end = 24,
		.l4_type = DR_STE_ACTION_MDFY_TYPE_L4_TCP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_SPORT] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L4_OUT_0, .start = 16, .end = 31,
		.l4_type = DR_STE_ACTION_MDFY_TYPE_L4_TCP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_DPORT] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L4_OUT_0, .start = 0, .end = 15,
		.l4_type = DR_STE_ACTION_MDFY_TYPE_L4_TCP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_IP_TTL] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L3_OUT_0, .start = 8, .end = 15,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV4,
	},
	[MLX5_ACTION_IN_FIELD_OUT_IPV6_HOPLIMIT] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L3_OUT_0, .start = 8, .end = 15,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_UDP_SPORT] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L4_OUT_0, .start = 16, .end = 31,
		.l4_type = DR_STE_ACTION_MDFY_TYPE_L4_UDP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_UDP_DPORT] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L4_OUT_0, .start = 0, .end = 15,
		.l4_type = DR_STE_ACTION_MDFY_TYPE_L4_UDP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV6_127_96] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_IPV6_SRC_OUT_0, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV6_95_64] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_IPV6_SRC_OUT_1, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV6_63_32] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_IPV6_SRC_OUT_2, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV6_31_0] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_IPV6_SRC_OUT_3, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV6_127_96] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_IPV6_DST_OUT_0, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV6_95_64] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_IPV6_DST_OUT_1, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV6_63_32] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_IPV6_DST_OUT_2, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV6_31_0] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_IPV6_DST_OUT_3, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV4] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_IPV4_OUT_0, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV4,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV4] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_IPV4_OUT_1, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV4,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGA] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_GNRL_PURPOSE, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGB] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_METADATA_2_CQE, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_0] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_REGISTER_6, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_1] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_REGISTER_7, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_2] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_REGISTER_4, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_3] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_REGISTER_5, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_4] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_REGISTER_2, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_5] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_REGISTER_3, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_SEQ_NUM] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_TCP_MISC_0, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_ACK_NUM] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_TCP_MISC_1, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_FIRST_VID] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L2_OUT_2, .start = 0, .end = 15,
	},
	[MLX5_ACTION_IN_FIELD_OUT_GTPU_TEID] = {
		.flags = DR_STE_ACTION_MODIFY_FLAG_REQ_FLEX, .start = 0, .end = 31,
	},
};

static const struct dr_ste_action_modify_field dr_ste_v1_action_modify_flex_field_arr[] = {
	{.hw_field = DR_STE_V1_ACTION_MDFY_FLD_FLEX_PARSER_0, .start = 0, .end = 31,},
	{.hw_field = DR_STE_V1_ACTION_MDFY_FLD_FLEX_PARSER_1, .start = 0, .end = 31,},
	{.hw_field = DR_STE_V1_ACTION_MDFY_FLD_FLEX_PARSER_2, .start = 0, .end = 31,},
	{.hw_field = DR_STE_V1_ACTION_MDFY_FLD_FLEX_PARSER_3, .start = 0, .end = 31,},
	{.hw_field = DR_STE_V1_ACTION_MDFY_FLD_FLEX_PARSER_4, .start = 0, .end = 31,},
	{.hw_field = DR_STE_V1_ACTION_MDFY_FLD_FLEX_PARSER_5, .start = 0, .end = 31,},
	{.hw_field = DR_STE_V1_ACTION_MDFY_FLD_FLEX_PARSER_6, .start = 0, .end = 31,},
	{.hw_field = DR_STE_V1_ACTION_MDFY_FLD_FLEX_PARSER_7, .start = 0, .end = 31,},
};

static void dr_ste_v1_set_entry_type(uint8_t *hw_ste_p, uint8_t entry_type)
{
	DR_STE_SET(match_bwc_v1, hw_ste_p, entry_format, entry_type);
}

static void dr_ste_v1_set_miss_addr(uint8_t *hw_ste_p, uint64_t miss_addr)
{
	uint64_t index = miss_addr >> 6;

	DR_STE_SET(match_bwc_v1, hw_ste_p, miss_address_39_32, index >> 26);
	DR_STE_SET(match_bwc_v1, hw_ste_p, miss_address_31_6, index);
}

static uint64_t dr_ste_v1_get_miss_addr(uint8_t *hw_ste_p)
{
	uint64_t index =
		(DR_STE_GET(match_bwc_v1, hw_ste_p, miss_address_31_6) |
		 DR_STE_GET(match_bwc_v1, hw_ste_p, miss_address_39_32) << 26);

	return index << 6;
}

static void dr_ste_v1_set_byte_mask(uint8_t *hw_ste_p, uint16_t byte_mask)
{
	DR_STE_SET(match_bwc_v1, hw_ste_p, byte_mask, byte_mask);
}

static uint16_t dr_ste_v1_get_byte_mask(uint8_t *hw_ste_p)
{
	return DR_STE_GET(match_bwc_v1, hw_ste_p, byte_mask);
}

static void dr_ste_v1_set_lu_type(uint8_t *hw_ste_p, uint16_t lu_type)
{
	DR_STE_SET(match_bwc_v1, hw_ste_p, entry_format, lu_type >> 8);
	DR_STE_SET(match_bwc_v1, hw_ste_p, match_definer_ctx_idx, lu_type & 0xFF);
}

static void dr_ste_v1_set_next_lu_type(uint8_t *hw_ste_p, uint16_t lu_type)
{
	DR_STE_SET(match_bwc_v1, hw_ste_p, next_entry_format, lu_type >> 8);
	DR_STE_SET(match_bwc_v1, hw_ste_p, hash_definer_ctx_idx, lu_type & 0xFF);
}

static uint16_t dr_ste_v1_get_next_lu_type(uint8_t *hw_ste_p)
{
	uint8_t mode = DR_STE_GET(match_bwc_v1, hw_ste_p, next_entry_format);
	uint8_t index = DR_STE_GET(match_bwc_v1, hw_ste_p, hash_definer_ctx_idx);

	return (mode << 8 | index);
}

static void dr_ste_v1_set_hit_addr(uint8_t *hw_ste_p, uint64_t icm_addr, uint32_t ht_size)
{
	uint64_t index = (icm_addr >> 5) | ht_size;

	DR_STE_SET(match_bwc_v1, hw_ste_p, next_table_base_39_32_size, index >> 27);
	DR_STE_SET(match_bwc_v1, hw_ste_p, next_table_base_31_5_size, index);
}

static void dr_ste_v1_init(uint8_t *hw_ste_p, uint16_t lu_type,
			   uint8_t entry_type, uint16_t gvmi)
{
	dr_ste_v1_set_lu_type(hw_ste_p, lu_type);
	dr_ste_v1_set_next_lu_type(hw_ste_p, DR_STE_LU_TYPE_DONT_CARE);

	DR_STE_SET(match_bwc_v1, hw_ste_p, gvmi, gvmi);
	DR_STE_SET(match_bwc_v1, hw_ste_p, next_table_base_63_48, gvmi);
	DR_STE_SET(match_bwc_v1, hw_ste_p, miss_address_63_48, gvmi);
}

static void dr_ste_v1_prepare_for_postsend(uint8_t *hw_ste_p,
					   uint32_t ste_size)
{
	uint8_t *tag = hw_ste_p + DR_STE_SIZE_CTRL;
	uint8_t *mask = tag + DR_STE_SIZE_TAG;
	uint8_t tmp_tag[DR_STE_SIZE_TAG] = {};

	if (ste_size == DR_STE_SIZE_CTRL)
		return;

	if (ste_size != DR_STE_SIZE)
		assert(false);

	/* Backup tag */
	memcpy(tmp_tag, tag, DR_STE_SIZE_TAG);

	/* Swap mask and tag  both are the same size */
	memcpy(tag, mask, DR_STE_SIZE_MASK);
	memcpy(mask, tmp_tag, DR_STE_SIZE_TAG);
}

static void dr_ste_v1_set_rx_flow_tag(uint8_t *s_action, uint32_t flow_tag)
{
	DR_STE_SET(single_action_flow_tag_v1, s_action, action_id,
		   DR_STE_V1_ACTION_ID_FLOW_TAG);
	DR_STE_SET(single_action_flow_tag_v1, s_action, flow_tag, flow_tag);
}

static void dr_ste_v1_set_counter_id(uint8_t *hw_ste_p, uint32_t ctr_id)
{
	DR_STE_SET(match_bwc_v1, hw_ste_p, counter_id, ctr_id);
}

static void dr_ste_v1_set_reparse(uint8_t *hw_ste_p)
{
	DR_STE_SET(match_bwc_v1, hw_ste_p, reparse, 1);
}

static void dr_ste_v1_set_tx_encap(uint8_t *hw_ste_p, uint8_t *d_action,
				   uint32_t reformat_id, int size)
{
	DR_STE_SET(double_action_insert_with_ptr_v1, d_action, action_id,
		   DR_STE_V1_ACTION_ID_INSERT_POINTER);
	/* The hardware expects here size in words (2 bytes) */
	DR_STE_SET(double_action_insert_with_ptr_v1, d_action, size, size / 2);
	DR_STE_SET(double_action_insert_with_ptr_v1, d_action, pointer, reformat_id);
	DR_STE_SET(double_action_insert_with_ptr_v1, d_action, attributes,
		   DR_STE_V1_ACTION_INSERT_PTR_ATTR_ENCAP);

	dr_ste_v1_set_reparse(hw_ste_p);
}

static void dr_ste_v1_set_push_vlan(uint8_t *ste, uint8_t *d_action,
				    uint32_t vlan_hdr)
{
	DR_STE_SET(double_action_insert_with_inline_v1, d_action, action_id,
		   DR_STE_V1_ACTION_ID_INSERT_INLINE);
	/* The hardware expects here offset to vlan header in words (2 byte) */
	DR_STE_SET(double_action_insert_with_inline_v1, d_action, start_offset,
		   HDR_LEN_L2_MACS >> 1);
	DR_STE_SET(double_action_insert_with_inline_v1, d_action, inline_data, vlan_hdr);
	dr_ste_v1_set_reparse(ste);
}

static void dr_ste_v1_set_pop_vlan(uint8_t *hw_ste_p, uint8_t *s_action,
				   uint8_t vlans_num)
{
	DR_STE_SET(single_action_remove_header_size_v1, s_action, action_id,
		   DR_STE_V1_ACTION_ID_REMOVE_BY_SIZE);
	DR_STE_SET(single_action_remove_header_size_v1, s_action, start_anchor,
		   DR_STE_HEADER_ANCHOR_1ST_VLAN);
	/* The hardware expects here size in words (2 byte) */
	DR_STE_SET(single_action_remove_header_size_v1, s_action, remove_size,
		   (HDR_LEN_L2_VLAN >> 1) * vlans_num);

	dr_ste_v1_set_reparse(hw_ste_p);
}

static void dr_ste_v1_set_tx_encap_l3(uint8_t *hw_ste_p,
				      uint8_t *frst_s_action,
				      uint8_t *scnd_d_action,
				      uint32_t reformat_id,
				      int size)
{
	/* Remove L2 headers */
	DR_STE_SET(single_action_remove_header_v1, frst_s_action, action_id,
		   DR_STE_V1_ACTION_ID_REMOVE_HEADER_TO_HEADER);
	DR_STE_SET(single_action_remove_header_v1, frst_s_action, end_anchor,
		   DR_STE_HEADER_ANCHOR_IPV6_IPV4);

	/* Encapsulate with given reformat ID */
	DR_STE_SET(double_action_insert_with_ptr_v1, scnd_d_action, action_id,
		   DR_STE_V1_ACTION_ID_INSERT_POINTER);
	/* The hardware expects here size in words (2 bytes) */
	DR_STE_SET(double_action_insert_with_ptr_v1, scnd_d_action, size, size / 2);
	DR_STE_SET(double_action_insert_with_ptr_v1, scnd_d_action, pointer, reformat_id);
	DR_STE_SET(double_action_insert_with_ptr_v1, scnd_d_action, attributes,
		   DR_STE_V1_ACTION_INSERT_PTR_ATTR_ENCAP);

	dr_ste_v1_set_reparse(hw_ste_p);
}

static void dr_ste_v1_set_rx_decap(uint8_t *hw_ste_p, uint8_t *s_action)
{
	DR_STE_SET(single_action_remove_header_v1, s_action, action_id,
		   DR_STE_V1_ACTION_ID_REMOVE_HEADER_TO_HEADER);
	DR_STE_SET(single_action_remove_header_v1, s_action, decap, 1);
	DR_STE_SET(single_action_remove_header_v1, s_action, vni_to_cqe, 1);
	DR_STE_SET(single_action_remove_header_v1, s_action, end_anchor,
		   DR_STE_HEADER_ANCHOR_INNER_MAC);

	dr_ste_v1_set_reparse(hw_ste_p);
}

static void dr_ste_v1_set_rx_decap_l3(uint8_t *hw_ste_p,
				      uint8_t *s_action,
				      uint16_t decap_actions,
				      uint32_t decap_index)
{
	DR_STE_SET(single_action_modify_list_v1, s_action, action_id,
		   DR_STE_V1_ACTION_ID_MODIFY_LIST);
	DR_STE_SET(single_action_modify_list_v1, s_action, num_of_modify_actions,
		   decap_actions);
	DR_STE_SET(single_action_modify_list_v1, s_action, modify_actions_ptr,
		   decap_index);

	dr_ste_v1_set_reparse(hw_ste_p);
}

static void dr_ste_v1_set_rewrite_actions(uint8_t *hw_ste_p,
					  uint8_t *s_action,
					  uint16_t num_of_actions,
					  uint32_t re_write_index)
{
	DR_STE_SET(single_action_modify_list_v1, s_action, action_id,
		   DR_STE_V1_ACTION_ID_MODIFY_LIST);
	DR_STE_SET(single_action_modify_list_v1, s_action, num_of_modify_actions,
		   num_of_actions);
	DR_STE_SET(single_action_modify_list_v1, s_action, modify_actions_ptr,
		   re_write_index);

	dr_ste_v1_set_reparse(hw_ste_p);
}

static inline void dr_ste_v1_arr_init_next_match(uint8_t **last_ste,
						 uint32_t *added_stes,
						 uint16_t gvmi)
{
	uint8_t *action;

	(*added_stes)++;
	*last_ste += DR_STE_SIZE;
	dr_ste_v1_init(*last_ste, DR_STE_LU_TYPE_DONT_CARE, 0, gvmi);
	dr_ste_v1_set_entry_type(*last_ste, DR_STE_V1_TYPE_MATCH);

	action = DEVX_ADDR_OF(ste_mask_and_match_v1, *last_ste, action);
	memset(action, 0, DEVX_FLD_SZ_BYTES(ste_mask_and_match_v1, action));
}

static void dr_ste_v1_set_aso_first_hit(uint8_t *d_action,
					uint32_t object_id,
					uint32_t offset,
					uint8_t dest_reg_id,
					bool set)
{
	DR_STE_SET(double_action_aso_v1, d_action, action_id,
		   DR_STE_V1_ACTION_ID_ASO);
	DR_STE_SET(double_action_aso_v1, d_action, aso_context_number,
		   object_id + (offset / MLX5_ASO_FIRST_HIT_NUM_PER_OBJ));
	/* Convert reg_c index to HW 64bit index */
	DR_STE_SET(double_action_aso_v1, d_action, dest_reg_id, (dest_reg_id - 1) / 2);
	DR_STE_SET(double_action_aso_v1, d_action, aso_context_type,
		   DR_STE_V1_ASO_CTX_TYPE_FIRST_HIT);
	DR_STE_SET(double_action_aso_v1, d_action, first_hit.line_id,
		   offset % MLX5_ASO_FIRST_HIT_NUM_PER_OBJ);
	/* In HW 0 is for set and 1 is for just read */
	DR_STE_SET(double_action_aso_v1, d_action, first_hit.set, !set);
}

static void dr_ste_v1_set_aso_flow_meter(uint8_t *d_action,
					 uint32_t object_id,
					 uint32_t offset,
					 uint8_t dest_reg_id,
					 uint8_t initial_color)
{
	DR_STE_SET(double_action_aso_v1, d_action, action_id,
		   DR_STE_V1_ACTION_ID_ASO);
	DR_STE_SET(double_action_aso_v1, d_action, aso_context_number,
		   object_id + (offset / MLX5_ASO_FLOW_METER_NUM_PER_OBJ));
	/* Convert reg_c index to HW 64bit index */
	DR_STE_SET(double_action_aso_v1, d_action, dest_reg_id, (dest_reg_id - 1) / 2);
	DR_STE_SET(double_action_aso_v1, d_action, aso_context_type,
		   DR_STE_V1_ASO_CTX_TYPE_POLICERS);
	DR_STE_SET(double_action_aso_v1, d_action, flow_meter.line_id,
		   offset % MLX5_ASO_FLOW_METER_NUM_PER_OBJ);
	DR_STE_SET(double_action_aso_v1, d_action, flow_meter.initial_color,
		   initial_color);
}

static void dr_ste_v1_set_aso_ct(uint8_t *d_action,
				 uint32_t object_id,
				 uint32_t offset,
				 uint8_t dest_reg_id,
				 bool direction)
{
	DR_STE_SET(double_action_aso_v1, d_action, action_id,
		   DR_STE_V1_ACTION_ID_ASO);
	DR_STE_SET(double_action_aso_v1, d_action, aso_context_number,
		   object_id + (offset / MLX5_ASO_CT_NUM_PER_OBJ));
	/* Convert reg_c index to HW 64bit index */
	DR_STE_SET(double_action_aso_v1, d_action, dest_reg_id, (dest_reg_id - 1) / 2);
	DR_STE_SET(double_action_aso_v1, d_action, aso_context_type,
		   DR_STE_V1_ASO_CTX_TYPE_CT);
	DR_STE_SET(double_action_aso_v1, d_action, ct.direction, direction);
}

static void dr_ste_v1_set_actions_tx(uint8_t *action_type_set,
				     uint8_t *last_ste,
				     struct dr_ste_actions_attr *attr,
				     uint32_t *added_stes)
{
	uint8_t *action = DEVX_ADDR_OF(ste_match_bwc_v1, last_ste, action);
	uint8_t action_sz = DR_STE_ACTION_DOUBLE_SZ;
	bool allow_modify_hdr = true;
	bool allow_pop_vlan = true;
	bool allow_encap = true;

	if (action_type_set[DR_ACTION_TYP_ASO_FLOW_METER]) {
		if (action_sz < DR_STE_ACTION_DOUBLE_SZ) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes,
						      attr->gvmi);
			action = DEVX_ADDR_OF(ste_mask_and_match_v1, last_ste,
					      action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
			allow_pop_vlan = false;
		}

		dr_ste_v1_set_aso_flow_meter(action,
					     attr->aso->devx_obj->object_id,
					     attr->aso->offset,
					     attr->aso->dest_reg_id,
					     attr->aso->flow_meter.initial_color);

		action_sz -= DR_STE_ACTION_DOUBLE_SZ;
		action += DR_STE_ACTION_DOUBLE_SZ;
	}

	if (action_type_set[DR_ACTION_TYP_POP_VLAN]) {
		if (action_sz < DR_STE_ACTION_SINGLE_SZ || !allow_pop_vlan) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes,
						      attr->gvmi);
			action = DEVX_ADDR_OF(ste_mask_and_match_v1, last_ste,
					      action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
		}
		dr_ste_v1_set_pop_vlan(last_ste, action, attr->vlans.count);
		action_sz -= DR_STE_ACTION_SINGLE_SZ;
		action += DR_STE_ACTION_SINGLE_SZ;
		allow_modify_hdr = false;
	}

	if (action_type_set[DR_ACTION_TYP_ASO_CT]) {
		if (action_sz < DR_STE_ACTION_DOUBLE_SZ) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes,
						      attr->gvmi);
			action = DEVX_ADDR_OF(ste_mask_and_match_v1,
					      last_ste, action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
		}
		dr_ste_v1_set_aso_ct(action,
				     attr->aso->devx_obj->object_id,
				     attr->aso->offset,
				     attr->aso->dest_reg_id,
				     attr->aso->ct.direction);

		action_sz -= DR_STE_ACTION_DOUBLE_SZ;
		action += DR_STE_ACTION_DOUBLE_SZ;
	}

	if (action_type_set[DR_ACTION_TYP_CTR])
		dr_ste_v1_set_counter_id(last_ste, attr->ctr_id);

	if (action_type_set[DR_ACTION_TYP_MODIFY_HDR]) {
		if (!allow_modify_hdr || action_sz < DR_STE_ACTION_DOUBLE_SZ) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes,
						      attr->gvmi);
			action = DEVX_ADDR_OF(ste_mask_and_match_v1,
					      last_ste, action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
		}
		dr_ste_v1_set_rewrite_actions(last_ste, action,
					      attr->modify_actions,
					      attr->modify_index);
		action_sz -= DR_STE_ACTION_DOUBLE_SZ;
		action += DR_STE_ACTION_DOUBLE_SZ;
		allow_encap = false;
	}

	if (action_type_set[DR_ACTION_TYP_PUSH_VLAN]) {
		int i;

		for (i = 0; i < attr->vlans.count; i++) {
			if (action_sz < DR_STE_ACTION_DOUBLE_SZ || !allow_encap) {
				dr_ste_v1_arr_init_next_match(&last_ste, added_stes, attr->gvmi);
				action = DEVX_ADDR_OF(ste_mask_and_match_v1, last_ste, action);
				action_sz = DR_STE_ACTION_TRIPLE_SZ;
				allow_encap = true;
			}
			dr_ste_v1_set_push_vlan(last_ste, action,
						attr->vlans.headers[i]);
			action_sz -= DR_STE_ACTION_DOUBLE_SZ;
			action += DR_STE_ACTION_DOUBLE_SZ;
		}
	}

	if (action_type_set[DR_ACTION_TYP_ASO_FIRST_HIT]) {
		if (action_sz < DR_STE_ACTION_DOUBLE_SZ) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes,
						      attr->gvmi);
			action = DEVX_ADDR_OF(ste_mask_and_match_v1,
					      last_ste, action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
			allow_encap = true;
		}
		dr_ste_v1_set_aso_first_hit(action,
					    attr->aso->devx_obj->object_id,
					    attr->aso->offset,
					    attr->aso->dest_reg_id,
					    attr->aso->first_hit.set);

		action_sz -= DR_STE_ACTION_DOUBLE_SZ;
		action += DR_STE_ACTION_DOUBLE_SZ;
	}

	if (action_type_set[DR_ACTION_TYP_L2_TO_TNL_L2]) {
		if (!allow_encap || action_sz < DR_STE_ACTION_DOUBLE_SZ) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes, attr->gvmi);
			action = DEVX_ADDR_OF(ste_mask_and_match_v1, last_ste, action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
			allow_encap = true;
		}
		dr_ste_v1_set_tx_encap(last_ste, action,
				       attr->reformat_id,
				       attr->reformat_size);
		action_sz -= DR_STE_ACTION_DOUBLE_SZ;
		action += DR_STE_ACTION_DOUBLE_SZ;
	} else if (action_type_set[DR_ACTION_TYP_L2_TO_TNL_L3]) {
		uint8_t *d_action;

		dr_ste_v1_arr_init_next_match(&last_ste, added_stes, attr->gvmi);
		action = DEVX_ADDR_OF(ste_mask_and_match_v1, last_ste, action);
		action_sz = DR_STE_ACTION_TRIPLE_SZ;
		d_action = action + DR_STE_ACTION_SINGLE_SZ;

		dr_ste_v1_set_tx_encap_l3(last_ste,
					  action, d_action,
					  attr->reformat_id,
					  attr->reformat_size);
		action_sz -= DR_STE_ACTION_TRIPLE_SZ;
		action += DR_STE_ACTION_TRIPLE_SZ;
	}

	dr_ste_v1_set_hit_addr(last_ste, attr->final_icm_addr, 1);
}

static void dr_ste_v1_set_actions_rx(uint8_t *action_type_set,
				     uint8_t *last_ste,
				     struct dr_ste_actions_attr *attr,
				     uint32_t *added_stes)
{
	uint8_t *action = DEVX_ADDR_OF(ste_match_bwc_v1, last_ste, action);
	uint8_t action_sz = DR_STE_ACTION_DOUBLE_SZ;
	bool allow_modify_hdr = true;
	bool allow_ctr = true;

	if (action_type_set[DR_ACTION_TYP_TNL_L3_TO_L2]) {
		dr_ste_v1_set_rx_decap_l3(last_ste, action,
					  attr->decap_actions,
					  attr->decap_index);
		action_sz -= DR_STE_ACTION_DOUBLE_SZ;
		action += DR_STE_ACTION_DOUBLE_SZ;
		allow_modify_hdr = false;
		allow_ctr = false;
	} else if (action_type_set[DR_ACTION_TYP_TNL_L2_TO_L2]) {
		dr_ste_v1_set_rx_decap(last_ste, action);
		action_sz -= DR_STE_ACTION_SINGLE_SZ;
		action += DR_STE_ACTION_SINGLE_SZ;
		allow_modify_hdr = false;
		allow_ctr = false;
	}

	if (action_type_set[DR_ACTION_TYP_TAG]) {
		if (action_sz < DR_STE_ACTION_SINGLE_SZ) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes, attr->gvmi);
			action = DEVX_ADDR_OF(ste_mask_and_match_v1, last_ste, action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
			allow_modify_hdr = true;
			allow_ctr = true;
		}
		dr_ste_v1_set_rx_flow_tag(action, attr->flow_tag);
		action_sz -= DR_STE_ACTION_SINGLE_SZ;
		action += DR_STE_ACTION_SINGLE_SZ;
	}

	if (action_type_set[DR_ACTION_TYP_POP_VLAN]) {
		if (action_sz < DR_STE_ACTION_SINGLE_SZ ||
		    !allow_modify_hdr) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes, attr->gvmi);
			action = DEVX_ADDR_OF(ste_mask_and_match_v1, last_ste, action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
			allow_modify_hdr = false;
			allow_ctr = false;
		}

		dr_ste_v1_set_pop_vlan(last_ste, action, attr->vlans.count);
		action_sz -= DR_STE_ACTION_SINGLE_SZ;
		action += DR_STE_ACTION_SINGLE_SZ;
	}

	if (action_type_set[DR_ACTION_TYP_ASO_FIRST_HIT]) {
		if (action_sz < DR_STE_ACTION_DOUBLE_SZ) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes,
						      attr->gvmi);
			action = DEVX_ADDR_OF(ste_mask_and_match_v1, last_ste,
					      action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
			allow_modify_hdr = true;
			allow_ctr = true;
		}
		dr_ste_v1_set_aso_first_hit(action,
					    attr->aso->devx_obj->object_id,
					    attr->aso->offset,
					    attr->aso->dest_reg_id,
					    attr->aso->first_hit.set);

		action_sz -= DR_STE_ACTION_DOUBLE_SZ;
		action += DR_STE_ACTION_DOUBLE_SZ;
	}

	if (action_type_set[DR_ACTION_TYP_MODIFY_HDR]) {
		/* Modify header and decapsulation must use different STEs */
		if (!allow_modify_hdr || action_sz < DR_STE_ACTION_DOUBLE_SZ) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes, attr->gvmi);
			action = DEVX_ADDR_OF(ste_mask_and_match_v1, last_ste, action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
			allow_modify_hdr = true;
			allow_ctr = true;
		}
		dr_ste_v1_set_rewrite_actions(last_ste, action,
					      attr->modify_actions,
					      attr->modify_index);
		action_sz -= DR_STE_ACTION_DOUBLE_SZ;
		action += DR_STE_ACTION_DOUBLE_SZ;
	}

	if (action_type_set[DR_ACTION_TYP_PUSH_VLAN]) {
		int i;

		for (i = 0; i < attr->vlans.count; i++) {
			if (action_sz < DR_STE_ACTION_DOUBLE_SZ ||
			    !allow_modify_hdr) {
				dr_ste_v1_arr_init_next_match(&last_ste,
							      added_stes,
							      attr->gvmi);
				action = DEVX_ADDR_OF(ste_mask_and_match_v1,
						      last_ste, action);
				action_sz = DR_STE_ACTION_TRIPLE_SZ;
			}
			dr_ste_v1_set_push_vlan(last_ste, action,
						attr->vlans.headers[i]);
			action_sz -= DR_STE_ACTION_DOUBLE_SZ;
			action += DR_STE_ACTION_DOUBLE_SZ;
		}
	}

	if (action_type_set[DR_ACTION_TYP_ASO_FLOW_METER]) {
		if (action_sz < DR_STE_ACTION_DOUBLE_SZ) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes,
						      attr->gvmi);
			action = DEVX_ADDR_OF(ste_mask_and_match_v1, last_ste,
					      action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
			allow_modify_hdr = false;
			allow_ctr = true;
		}
		dr_ste_v1_set_aso_flow_meter(action,
					     attr->aso->devx_obj->object_id,
					     attr->aso->offset,
					     attr->aso->dest_reg_id,
					     attr->aso->flow_meter.initial_color);

		action_sz -= DR_STE_ACTION_DOUBLE_SZ;
		action += DR_STE_ACTION_DOUBLE_SZ;
	}

	if (action_type_set[DR_ACTION_TYP_ASO_CT]) {
		if (action_sz < DR_STE_ACTION_DOUBLE_SZ) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes,
						      attr->gvmi);
			action = DEVX_ADDR_OF(ste_mask_and_match_v1, last_ste,
					      action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
			allow_modify_hdr = false;
			allow_ctr = true;
		}
		dr_ste_v1_set_aso_ct(action,
				     attr->aso->devx_obj->object_id,
				     attr->aso->offset,
				     attr->aso->dest_reg_id,
				     attr->aso->ct.direction);

		action_sz -= DR_STE_ACTION_DOUBLE_SZ;
		action += DR_STE_ACTION_DOUBLE_SZ;
	}

	if (action_type_set[DR_ACTION_TYP_CTR]) {
		/* Counter action set after decap to exclude decaped header */
		if (!allow_ctr) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes, attr->gvmi);
			action = DEVX_ADDR_OF(ste_mask_and_match_v1, last_ste, action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
			allow_modify_hdr = true;
			allow_ctr = false;
		}
		dr_ste_v1_set_counter_id(last_ste, attr->ctr_id);
	}

	dr_ste_v1_set_hit_addr(last_ste, attr->final_icm_addr, 1);
}

static void dr_ste_v1_set_action_set(uint8_t *d_action,
				     uint8_t hw_field,
				     uint8_t shifter,
				     uint8_t length,
				     uint32_t data)
{
	shifter += MLX5_MODIFY_HEADER_V1_QW_OFFSET;
	DR_STE_SET(double_action_set_v1, d_action, action_id, DR_STE_V1_ACTION_ID_SET);
	DR_STE_SET(double_action_set_v1, d_action, destination_dw_offset, hw_field);
	DR_STE_SET(double_action_set_v1, d_action, destination_left_shifter, shifter);
	DR_STE_SET(double_action_set_v1, d_action, destination_length, length);
	DR_STE_SET(double_action_set_v1, d_action, inline_data, data);
}

static void dr_ste_v1_set_action_add(uint8_t *d_action,
				     uint8_t hw_field,
				     uint8_t shifter,
				     uint8_t length,
				     uint32_t data)
{
	shifter += MLX5_MODIFY_HEADER_V1_QW_OFFSET;
	DR_STE_SET(double_action_add_v1, d_action, action_id, DR_STE_V1_ACTION_ID_ADD);
	DR_STE_SET(double_action_add_v1, d_action, destination_dw_offset, hw_field);
	DR_STE_SET(double_action_add_v1, d_action, destination_left_shifter, shifter);
	DR_STE_SET(double_action_add_v1, d_action, destination_length, length);
	DR_STE_SET(double_action_add_v1, d_action, add_value, data);
}

static void dr_ste_v1_set_action_copy(uint8_t *d_action,
				      uint8_t dst_hw_field,
				      uint8_t dst_shifter,
				      uint8_t dst_len,
				      uint8_t src_hw_field,
				      uint8_t src_shifter)
{
	dst_shifter += MLX5_MODIFY_HEADER_V1_QW_OFFSET;
	src_shifter += MLX5_MODIFY_HEADER_V1_QW_OFFSET;
	DR_STE_SET(double_action_copy_v1, d_action, action_id, DR_STE_V1_ACTION_ID_COPY);
	DR_STE_SET(double_action_copy_v1, d_action, destination_dw_offset, dst_hw_field);
	DR_STE_SET(double_action_copy_v1, d_action, destination_left_shifter, dst_shifter);
	DR_STE_SET(double_action_copy_v1, d_action, destination_length, dst_len);
	DR_STE_SET(double_action_copy_v1, d_action, source_dw_offset, src_hw_field);
	DR_STE_SET(double_action_copy_v1, d_action, source_right_shifter, src_shifter);
}

#define DR_STE_DECAP_L3_ACTION_NUM	8
#define DR_STE_L2_HDR_MAX_SZ		20

static int
dr_ste_v1_set_action_decap_l3_list(void *data, uint32_t data_sz,
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

	memcpy(padded_data, data, data_sz);

	/* Remove L2L3 outer headers */
	DR_STE_SET(single_action_remove_header_v1, hw_action, action_id,
		   DR_STE_V1_ACTION_ID_REMOVE_HEADER_TO_HEADER);
	DR_STE_SET(single_action_remove_header_v1, hw_action, decap, 1);
	DR_STE_SET(single_action_remove_header_v1, hw_action, vni_to_cqe, 1);
	DR_STE_SET(single_action_remove_header_v1, hw_action, end_anchor,
		   DR_STE_HEADER_ANCHOR_INNER_IPV6_IPV4);
	hw_action += DR_STE_ACTION_DOUBLE_SZ;
	used_actions++;

	inline_data_sz =
		DEVX_FLD_SZ_BYTES(ste_double_action_insert_with_inline_v1, inline_data);

	/* Add the new header inline + 2 extra bytes */
	for (i = 0; i < data_sz / inline_data_sz + 1; i++) {
		void *addr_inline;

		DR_STE_SET(double_action_insert_with_inline_v1, hw_action, action_id,
			   DR_STE_V1_ACTION_ID_INSERT_INLINE);
		/* The hardware expects here offset to words (2 bytes) */
		DR_STE_SET(double_action_insert_with_inline_v1, hw_action, start_offset,
			   i * 2);

		/* Copy byte byte in order to skip endianness problem */
		addr_inline = DEVX_ADDR_OF(ste_double_action_insert_with_inline_v1,
					   hw_action, inline_data);
		memcpy(addr_inline, data_ptr, inline_data_sz);
		hw_action += DR_STE_ACTION_DOUBLE_SZ;
		data_ptr += inline_data_sz;
		used_actions++;
	}

	/* Remove 2 extra bytes */
	DR_STE_SET(single_action_remove_header_size_v1, hw_action, action_id,
		   DR_STE_V1_ACTION_ID_REMOVE_BY_SIZE);
	DR_STE_SET(single_action_remove_header_size_v1, hw_action, start_offset, data_sz / 2);
	/* The hardware expects here size in words (2 bytes) */
	DR_STE_SET(single_action_remove_header_size_v1, hw_action, remove_size, 1);
	used_actions++;

	*used_hw_action_num = used_actions;

	return 0;
}

static const struct dr_ste_action_modify_field *
dr_ste_v1_get_action_flex_hw_field(uint16_t sw_field, struct dr_devx_caps *caps)
{
	uint8_t flex_id;

	if (!caps->flex_parser_header_modify)
		goto not_found;

	if ((sw_field == MLX5_ACTION_IN_FIELD_OUT_GTPU_TEID) &&
	    (caps->flex_protocols & MLX5_FLEX_PARSER_GTPU_TEID_ENABLED))
		flex_id = caps->flex_parser_id_gtpu_teid;
	else
		goto not_found;

	if (flex_id >= ARRAY_SIZE(dr_ste_v1_action_modify_flex_field_arr))
		goto not_found;

	return &dr_ste_v1_action_modify_flex_field_arr[flex_id];

not_found:
	errno = EINVAL;
	return NULL;
}

static const struct dr_ste_action_modify_field *
dr_ste_v1_get_action_hw_field(uint16_t sw_field, struct dr_devx_caps *caps)
{
	const struct dr_ste_action_modify_field *hw_field;

	if (sw_field >= ARRAY_SIZE(dr_ste_v1_action_modify_field_arr))
		goto not_found;

	hw_field = &dr_ste_v1_action_modify_field_arr[sw_field];
	if (!hw_field->end && !hw_field->start)
		goto not_found;

	if (hw_field->flags & DR_STE_ACTION_MODIFY_FLAG_REQ_FLEX)
		return dr_ste_v1_get_action_flex_hw_field(sw_field, caps);

	return hw_field;

not_found:
	errno = EINVAL;
	return NULL;
}

static void dr_ste_v1_build_eth_l2_src_dst_bit_mask(struct dr_match_param *value,
						    bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l2_src_dst_v1, bit_mask, dmac_47_16, mask, dmac_47_16);
	DR_STE_SET_TAG(eth_l2_src_dst_v1, bit_mask, dmac_15_0, mask, dmac_15_0);

	DR_STE_SET_TAG(eth_l2_src_dst_v1, bit_mask, smac_47_16, mask, smac_47_16);
	DR_STE_SET_TAG(eth_l2_src_dst_v1, bit_mask, smac_15_0, mask, smac_15_0);

	DR_STE_SET_TAG(eth_l2_src_dst_v1, bit_mask, first_vlan_id, mask, first_vid);
	DR_STE_SET_TAG(eth_l2_src_dst_v1, bit_mask, first_cfi, mask, first_cfi);
	DR_STE_SET_TAG(eth_l2_src_dst_v1, bit_mask, first_priority, mask, first_prio);
	DR_STE_SET_ONES(eth_l2_src_dst_v1, bit_mask, l3_type, mask, ip_version);

	if (mask->cvlan_tag) {
		DR_STE_SET(eth_l2_src_dst_v1, bit_mask, first_vlan_qualifier, -1);
		mask->cvlan_tag = 0;
	} else if (mask->svlan_tag) {
		DR_STE_SET(eth_l2_src_dst_v1, bit_mask, first_vlan_qualifier, -1);
		mask->svlan_tag = 0;
	}
}

static int dr_ste_v1_build_eth_l2_src_dst_tag(struct dr_match_param *value,
					      struct dr_ste_build *sb,
					      uint8_t *tag)
{
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l2_src_dst_v1, tag, dmac_47_16, spec, dmac_47_16);
	DR_STE_SET_TAG(eth_l2_src_dst_v1, tag, dmac_15_0, spec, dmac_15_0);

	DR_STE_SET_TAG(eth_l2_src_dst_v1, tag, smac_47_16, spec, smac_47_16);
	DR_STE_SET_TAG(eth_l2_src_dst_v1, tag, smac_15_0, spec, smac_15_0);

	if (spec->ip_version) {
		if (spec->ip_version == IP_VERSION_IPV4) {
			DR_STE_SET(eth_l2_src_dst_v1, tag, l3_type, STE_IPV4);
			spec->ip_version = 0;
		} else if (spec->ip_version == IP_VERSION_IPV6) {
			DR_STE_SET(eth_l2_src_dst_v1, tag, l3_type, STE_IPV6);
			spec->ip_version = 0;
		} else {
			errno = EINVAL;
			return errno;
		}
	}

	DR_STE_SET_TAG(eth_l2_src_dst_v1, tag, first_vlan_id, spec, first_vid);
	DR_STE_SET_TAG(eth_l2_src_dst_v1, tag, first_cfi, spec, first_cfi);
	DR_STE_SET_TAG(eth_l2_src_dst_v1, tag, first_priority, spec, first_prio);

	if (spec->cvlan_tag) {
		DR_STE_SET(eth_l2_src_dst_v1, tag, first_vlan_qualifier, DR_STE_CVLAN);
		spec->cvlan_tag = 0;
	} else if (spec->svlan_tag) {
		DR_STE_SET(eth_l2_src_dst_v1, tag, first_vlan_qualifier, DR_STE_SVLAN);
		spec->svlan_tag = 0;
	}
	return 0;
}

static void dr_ste_v1_build_eth_l2_src_dst_init(struct dr_ste_build *sb,
						struct dr_match_param *mask)
{
	dr_ste_v1_build_eth_l2_src_dst_bit_mask(mask, sb->inner, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_DFNR_TYPE(ETHL2_SRC_DST, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_eth_l2_src_dst_tag;
}

static int dr_ste_v1_build_eth_l3_ipv6_dst_tag(struct dr_match_param *value,
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

static void dr_ste_v1_build_eth_l3_ipv6_dst_init(struct dr_ste_build *sb,
						 struct dr_match_param *mask)
{
	dr_ste_v1_build_eth_l3_ipv6_dst_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_DFNR_TYPE(IPV6_DES, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_eth_l3_ipv6_dst_tag;
}

static int dr_ste_v1_build_eth_l3_ipv6_src_tag(struct dr_match_param *value,
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

static void dr_ste_v1_build_eth_l3_ipv6_src_init(struct dr_ste_build *sb,
						 struct dr_match_param *mask)
{
	dr_ste_v1_build_eth_l3_ipv6_src_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_DFNR_TYPE(IPV6_SRC, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_eth_l3_ipv6_src_tag;
}

static int dr_ste_v1_build_eth_l3_ipv4_5_tuple_tag(struct dr_match_param *value,
						   struct dr_ste_build *sb,
						   uint8_t *tag)
{
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple_v1, tag, destination_address, spec, dst_ip_31_0);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple_v1, tag, source_address, spec, src_ip_31_0);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple_v1, tag, destination_port, spec, tcp_dport);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple_v1, tag, destination_port, spec, udp_dport);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple_v1, tag, source_port, spec, tcp_sport);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple_v1, tag, source_port, spec, udp_sport);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple_v1, tag, protocol, spec, ip_protocol);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple_v1, tag, fragmented, spec, frag);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple_v1, tag, dscp, spec, ip_dscp);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple_v1, tag, ecn, spec, ip_ecn);

	if (spec->tcp_flags) {
		DR_STE_SET_TCP_FLAGS(eth_l3_ipv4_5_tuple_v1, tag, spec);
		spec->tcp_flags = 0;
	}

	return 0;
}

static void dr_ste_v1_build_eth_l3_ipv4_5_tuple_init(struct dr_ste_build *sb,
						     struct dr_match_param *mask)
{
	dr_ste_v1_build_eth_l3_ipv4_5_tuple_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_DFNR_TYPE(ETHL3_IPV4_5_TUPLE, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_eth_l3_ipv4_5_tuple_tag;
}

static void dr_ste_v1_build_eth_l2_src_or_dst_bit_mask(struct dr_match_param *value,
						       bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;
	struct dr_match_misc *misc_mask = &value->misc;

	DR_STE_SET_TAG(eth_l2_src_v1, bit_mask, first_vlan_id, mask, first_vid);
	DR_STE_SET_TAG(eth_l2_src_v1, bit_mask, first_cfi, mask, first_cfi);
	DR_STE_SET_TAG(eth_l2_src_v1, bit_mask, first_priority, mask, first_prio);
	DR_STE_SET_TAG(eth_l2_src_v1, bit_mask, ip_fragmented, mask, frag); // ?
	DR_STE_SET_TAG(eth_l2_src_v1, bit_mask, l3_ethertype, mask, ethertype); // ?
	DR_STE_SET_ONES(eth_l2_src_v1, bit_mask, l3_type, mask, ip_version);

	if (mask->svlan_tag || mask->cvlan_tag) {
		DR_STE_SET(eth_l2_src_v1, bit_mask, first_vlan_qualifier, -1);
		mask->cvlan_tag = 0;
		mask->svlan_tag = 0;
	}

	if (inner) {
		if (misc_mask->inner_second_cvlan_tag ||
		    misc_mask->inner_second_svlan_tag) {
			DR_STE_SET(eth_l2_src_v1, bit_mask, second_vlan_qualifier, -1);
			misc_mask->inner_second_cvlan_tag = 0;
			misc_mask->inner_second_svlan_tag = 0;
		}

		DR_STE_SET_TAG(eth_l2_src_v1, bit_mask, second_vlan_id, misc_mask, inner_second_vid);
		DR_STE_SET_TAG(eth_l2_src_v1, bit_mask, second_cfi, misc_mask, inner_second_cfi);
		DR_STE_SET_TAG(eth_l2_src_v1, bit_mask, second_priority, misc_mask, inner_second_prio);
	} else {
		if (misc_mask->outer_second_cvlan_tag ||
		    misc_mask->outer_second_svlan_tag) {
			DR_STE_SET(eth_l2_src_v1, bit_mask, second_vlan_qualifier, -1);
			misc_mask->outer_second_cvlan_tag = 0;
			misc_mask->outer_second_svlan_tag = 0;
		}

		DR_STE_SET_TAG(eth_l2_src_v1, bit_mask, second_vlan_id, misc_mask, outer_second_vid);
		DR_STE_SET_TAG(eth_l2_src_v1, bit_mask, second_cfi, misc_mask, outer_second_cfi);
		DR_STE_SET_TAG(eth_l2_src_v1, bit_mask, second_priority, misc_mask, outer_second_prio);
	}
}

static int dr_ste_v1_build_eth_l2_src_or_dst_tag(struct dr_match_param *value,
						 bool inner, uint8_t *tag)
{
	struct dr_match_spec *spec = inner ? &value->inner : &value->outer;
	struct dr_match_misc *misc_spec = &value->misc;

	DR_STE_SET_TAG(eth_l2_src_v1, tag, first_vlan_id, spec, first_vid);
	DR_STE_SET_TAG(eth_l2_src_v1, tag, first_cfi, spec, first_cfi);
	DR_STE_SET_TAG(eth_l2_src_v1, tag, first_priority, spec, first_prio);
	DR_STE_SET_TAG(eth_l2_src_v1, tag, ip_fragmented, spec, frag);
	DR_STE_SET_TAG(eth_l2_src_v1, tag, l3_ethertype, spec, ethertype);

	if (spec->ip_version) {
		if (spec->ip_version == IP_VERSION_IPV4) {
			DR_STE_SET(eth_l2_src_v1, tag, l3_type, STE_IPV4);
			spec->ip_version = 0;
		} else if (spec->ip_version == IP_VERSION_IPV6) {
			DR_STE_SET(eth_l2_src_v1, tag, l3_type, STE_IPV6);
			spec->ip_version = 0;
		} else {
			errno = EINVAL;
			return errno;
		}
	}

	if (spec->cvlan_tag) {
		DR_STE_SET(eth_l2_src_v1, tag, first_vlan_qualifier, DR_STE_CVLAN);
		spec->cvlan_tag = 0;
	} else if (spec->svlan_tag) {
		DR_STE_SET(eth_l2_src_v1, tag, first_vlan_qualifier, DR_STE_SVLAN);
		spec->svlan_tag = 0;
	}

	if (inner) {
		if (misc_spec->inner_second_cvlan_tag) {
			DR_STE_SET(eth_l2_src_v1, tag, second_vlan_qualifier, DR_STE_CVLAN);
			misc_spec->inner_second_cvlan_tag = 0;
		} else if (misc_spec->inner_second_svlan_tag) {
			DR_STE_SET(eth_l2_src_v1, tag, second_vlan_qualifier, DR_STE_SVLAN);
			misc_spec->inner_second_svlan_tag = 0;
		}

		DR_STE_SET_TAG(eth_l2_src_v1, tag, second_vlan_id, misc_spec, inner_second_vid);
		DR_STE_SET_TAG(eth_l2_src_v1, tag, second_cfi, misc_spec, inner_second_cfi);
		DR_STE_SET_TAG(eth_l2_src_v1, tag, second_priority, misc_spec, inner_second_prio);
	} else {
		if (misc_spec->outer_second_cvlan_tag) {
			DR_STE_SET(eth_l2_src_v1, tag, second_vlan_qualifier, DR_STE_CVLAN);
			misc_spec->outer_second_cvlan_tag = 0;
		} else if (misc_spec->outer_second_svlan_tag) {
			DR_STE_SET(eth_l2_src_v1, tag, second_vlan_qualifier, DR_STE_SVLAN);
			misc_spec->outer_second_svlan_tag = 0;
		}
		DR_STE_SET_TAG(eth_l2_src_v1, tag, second_vlan_id, misc_spec, outer_second_vid);
		DR_STE_SET_TAG(eth_l2_src_v1, tag, second_cfi, misc_spec, outer_second_cfi);
		DR_STE_SET_TAG(eth_l2_src_v1, tag, second_priority, misc_spec, outer_second_prio);
	}

	return 0;
}

static void dr_ste_v1_build_eth_l2_src_bit_mask(struct dr_match_param *value,
						bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l2_src_v1, bit_mask, smac_47_16, mask, smac_47_16);
	DR_STE_SET_TAG(eth_l2_src_v1, bit_mask, smac_15_0, mask, smac_15_0);

	dr_ste_v1_build_eth_l2_src_or_dst_bit_mask(value, inner, bit_mask);
}

static int dr_ste_v1_build_eth_l2_src_tag(struct dr_match_param *value,
					  struct dr_ste_build *sb,
					  uint8_t *tag)
{
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l2_src_v1, tag, smac_47_16, spec, smac_47_16);
	DR_STE_SET_TAG(eth_l2_src_v1, tag, smac_15_0, spec, smac_15_0);

	return dr_ste_v1_build_eth_l2_src_or_dst_tag(value, sb->inner, tag);
}

static void dr_ste_v1_build_eth_l2_src_init(struct dr_ste_build *sb,
					    struct dr_match_param *mask)
{
	dr_ste_v1_build_eth_l2_src_bit_mask(mask, sb->inner, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_DFNR_TYPE(ETHL2_SRC, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_eth_l2_src_tag;
}

static void dr_ste_v1_build_eth_l2_dst_bit_mask(struct dr_match_param *value,
						bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l2_dst_v1, bit_mask, dmac_47_16, mask, dmac_47_16);
	DR_STE_SET_TAG(eth_l2_dst_v1, bit_mask, dmac_15_0, mask, dmac_15_0);

	dr_ste_v1_build_eth_l2_src_or_dst_bit_mask(value, inner, bit_mask);
}

static int dr_ste_v1_build_eth_l2_dst_tag(struct dr_match_param *value,
					  struct dr_ste_build *sb,
					  uint8_t *tag)
{
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l2_dst_v1, tag, dmac_47_16, spec, dmac_47_16);
	DR_STE_SET_TAG(eth_l2_dst_v1, tag, dmac_15_0, spec, dmac_15_0);

	return dr_ste_v1_build_eth_l2_src_or_dst_tag(value, sb->inner, tag);
}

static void dr_ste_v1_build_eth_l2_dst_init(struct dr_ste_build *sb,
					    struct dr_match_param *mask)
{
	dr_ste_v1_build_eth_l2_dst_bit_mask(mask, sb->inner, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_DFNR_TYPE(ETHL2, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_eth_l2_dst_tag;
}

static void dr_ste_v1_build_eth_l2_tnl_bit_mask(struct dr_match_param *value,
						bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;
	struct dr_match_misc *misc = &value->misc;

	DR_STE_SET_TAG(eth_l2_tnl_v1, bit_mask, dmac_47_16, mask, dmac_47_16);
	DR_STE_SET_TAG(eth_l2_tnl_v1, bit_mask, dmac_15_0, mask, dmac_15_0);
	DR_STE_SET_TAG(eth_l2_tnl_v1, bit_mask, first_vlan_id, mask, first_vid);
	DR_STE_SET_TAG(eth_l2_tnl_v1, bit_mask, first_cfi, mask, first_cfi);
	DR_STE_SET_TAG(eth_l2_tnl_v1, bit_mask, first_priority, mask, first_prio);
	DR_STE_SET_TAG(eth_l2_tnl_v1, bit_mask, ip_fragmented, mask, frag);
	DR_STE_SET_TAG(eth_l2_tnl_v1, bit_mask, l3_ethertype, mask, ethertype);
	DR_STE_SET_ONES(eth_l2_tnl_v1, bit_mask, l3_type, mask, ip_version);

	if (misc->vxlan_vni) {
		DR_STE_SET(eth_l2_tnl_v1, bit_mask, l2_tunneling_network_id, (misc->vxlan_vni << 8));
		misc->vxlan_vni = 0;
	}

	if (mask->svlan_tag || mask->cvlan_tag) {
		DR_STE_SET(eth_l2_tnl_v1, bit_mask, first_vlan_qualifier, -1);
		mask->cvlan_tag = 0;
		mask->svlan_tag = 0;
	}
}

static int dr_ste_v1_build_eth_l2_tnl_tag(struct dr_match_param *value,
					  struct dr_ste_build *sb,
					  uint8_t *tag)
{
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;
	struct dr_match_misc *misc = &value->misc;

	DR_STE_SET_TAG(eth_l2_tnl_v1, tag, dmac_47_16, spec, dmac_47_16);
	DR_STE_SET_TAG(eth_l2_tnl_v1, tag, dmac_15_0, spec, dmac_15_0);
	DR_STE_SET_TAG(eth_l2_tnl_v1, tag, first_vlan_id, spec, first_vid);
	DR_STE_SET_TAG(eth_l2_tnl_v1, tag, first_cfi, spec, first_cfi);
	DR_STE_SET_TAG(eth_l2_tnl_v1, tag, ip_fragmented, spec, frag);
	DR_STE_SET_TAG(eth_l2_tnl_v1, tag, first_priority, spec, first_prio);
	DR_STE_SET_TAG(eth_l2_tnl_v1, tag, l3_ethertype, spec, ethertype);

	if (misc->vxlan_vni) {
		DR_STE_SET(eth_l2_tnl_v1, tag, l2_tunneling_network_id,
			   (misc->vxlan_vni << 8));
		misc->vxlan_vni = 0;
	}

	if (spec->cvlan_tag) {
		DR_STE_SET(eth_l2_tnl_v1, tag, first_vlan_qualifier, DR_STE_CVLAN);
		spec->cvlan_tag = 0;
	} else if (spec->svlan_tag) {
		DR_STE_SET(eth_l2_tnl_v1, tag, first_vlan_qualifier, DR_STE_SVLAN);
		spec->svlan_tag = 0;
	}

	if (spec->ip_version) {
		if (spec->ip_version == IP_VERSION_IPV4) {
			DR_STE_SET(eth_l2_tnl_v1, tag, l3_type, STE_IPV4);
			spec->ip_version = 0;
		} else if (spec->ip_version == IP_VERSION_IPV6) {
			DR_STE_SET(eth_l2_tnl_v1, tag, l3_type, STE_IPV6);
			spec->ip_version = 0;
		} else {
			errno = EINVAL;
			return errno;
		}
	}

	return 0;
}

static void dr_ste_v1_build_eth_l2_tnl_init(struct dr_ste_build *sb,
					    struct dr_match_param *mask)
{
	dr_ste_v1_build_eth_l2_tnl_bit_mask(mask, sb->inner, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_ETHL2_TNL;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_eth_l2_tnl_tag;
}

static int dr_ste_v1_build_eth_l3_ipv4_misc_tag(struct dr_match_param *value,
						struct dr_ste_build *sb,
						uint8_t *tag)
{
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l3_ipv4_misc_v1, tag, time_to_live, spec, ip_ttl_hoplimit);

	return 0;
}

static void dr_ste_v1_build_eth_l3_ipv4_misc_init(struct dr_ste_build *sb,
						  struct dr_match_param *mask)
{
	dr_ste_v1_build_eth_l3_ipv4_misc_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_DFNR_TYPE(ETHL3_IPV4_MISC, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_eth_l3_ipv4_misc_tag;
}

static int dr_ste_v1_build_eth_ipv6_l3_l4_tag(struct dr_match_param *value,
					      struct dr_ste_build *sb,
					      uint8_t *tag)
{
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;
	struct dr_match_misc *misc = &value->misc;

	DR_STE_SET_TAG(eth_l4_v1, tag, dst_port, spec, tcp_dport);
	DR_STE_SET_TAG(eth_l4_v1, tag, src_port, spec, tcp_sport);
	DR_STE_SET_TAG(eth_l4_v1, tag, dst_port, spec, udp_dport);
	DR_STE_SET_TAG(eth_l4_v1, tag, src_port, spec, udp_sport);
	DR_STE_SET_TAG(eth_l4_v1, tag, protocol, spec, ip_protocol);
	DR_STE_SET_TAG(eth_l4_v1, tag, fragmented, spec, frag);
	DR_STE_SET_TAG(eth_l4_v1, tag, dscp, spec, ip_dscp);
	DR_STE_SET_TAG(eth_l4_v1, tag, ecn, spec, ip_ecn);
	DR_STE_SET_TAG(eth_l4_v1, tag, ipv6_hop_limit, spec, ip_ttl_hoplimit);

	if (sb->inner)
		DR_STE_SET_TAG(eth_l4_v1, tag, flow_label, misc, inner_ipv6_flow_label);
	else
		DR_STE_SET_TAG(eth_l4_v1, tag, flow_label, misc, outer_ipv6_flow_label);

	if (spec->tcp_flags) {
		DR_STE_SET_TCP_FLAGS(eth_l4_v1, tag, spec);
		spec->tcp_flags = 0;
	}

	return 0;
}

static void dr_ste_v1_build_eth_ipv6_l3_l4_init(struct dr_ste_build *sb,
						struct dr_match_param *mask)
{
	dr_ste_v1_build_eth_ipv6_l3_l4_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_DFNR_TYPE(ETHL4, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_eth_ipv6_l3_l4_tag;
}

static int dr_ste_v1_build_mpls_tag(struct dr_match_param *value,
				    struct dr_ste_build *sb,
				    uint8_t *tag)
{
	struct dr_match_misc2 *misc2 = &value->misc2;

	if (sb->inner)
		DR_STE_SET_MPLS(mpls_v1, misc2, inner, tag);
	else
		DR_STE_SET_MPLS(mpls_v1, misc2, outer, tag);

	return 0;
}

static void dr_ste_v1_build_mpls_init(struct dr_ste_build *sb,
				      struct dr_match_param *mask)
{
	dr_ste_v1_build_mpls_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_DFNR_TYPE(MPLS, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_mpls_tag;
}

static int dr_ste_v1_build_tnl_gre_tag(struct dr_match_param *value,
				       struct dr_ste_build *sb,
				       uint8_t *tag)
{
	struct  dr_match_misc *misc = &value->misc;

	DR_STE_SET_TAG(gre_v1, tag, gre_protocol, misc, gre_protocol);
	DR_STE_SET_TAG(gre_v1, tag, gre_k_present, misc, gre_k_present);
	DR_STE_SET_TAG(gre_v1, tag, gre_key_h, misc, gre_key_h);
	DR_STE_SET_TAG(gre_v1, tag, gre_key_l, misc, gre_key_l);

	DR_STE_SET_TAG(gre_v1, tag, gre_c_present, misc, gre_c_present);
	DR_STE_SET_TAG(gre_v1, tag, gre_s_present, misc, gre_s_present);

	return 0;
}

static void dr_ste_v1_build_tnl_gre_init(struct dr_ste_build *sb,
					 struct dr_match_param *mask)
{
	dr_ste_v1_build_tnl_gre_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_GRE;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_tnl_gre_tag;
}

static int dr_ste_v1_build_tnl_mpls_over_udp_tag(struct dr_match_param *value,
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

static void dr_ste_v1_build_tnl_mpls_over_udp_init(struct dr_ste_build *sb,
						   struct dr_match_param *mask)
{
	dr_ste_v1_build_tnl_mpls_over_udp_tag(mask, sb, sb->bit_mask);

	/* STEs with lookup type FLEX_PARSER_{0/1} includes
	 * flex parsers_{0-3}/{4-7} respectively.
	 */
	sb->lu_type = sb->caps->flex_parser_id_mpls_over_udp <= DR_STE_MAX_FLEX_0_ID ?
		      DR_STE_V1_LU_TYPE_FLEX_PARSER_0 :
		      DR_STE_V1_LU_TYPE_FLEX_PARSER_1;

	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_tnl_mpls_over_udp_tag;
}

static int dr_ste_v1_build_tnl_mpls_over_gre_tag(struct dr_match_param *value,
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

static void dr_ste_v1_build_tnl_mpls_over_gre_init(struct dr_ste_build *sb,
						   struct dr_match_param *mask)
{
	dr_ste_v1_build_tnl_mpls_over_gre_tag(mask, sb, sb->bit_mask);

	/* STEs with lookup type FLEX_PARSER_{0/1} includes
	 * flex parsers_{0-3}/{4-7} respectively.
	 */
	sb->lu_type = sb->caps->flex_parser_id_mpls_over_gre <= DR_STE_MAX_FLEX_0_ID ?
		      DR_STE_V1_LU_TYPE_FLEX_PARSER_0 :
		      DR_STE_V1_LU_TYPE_FLEX_PARSER_1;

	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_tnl_mpls_over_gre_tag;
}

static int dr_ste_v1_build_icmp_tag(struct dr_match_param *value,
				    struct dr_ste_build *sb,
				    uint8_t *tag)
{
	struct dr_match_misc3 *misc3 = &value->misc3;
	bool is_ipv4 = DR_MASK_IS_ICMPV4_SET(misc3);
	uint32_t *icmp_header_data;
	uint8_t *icmp_type;
	uint8_t *icmp_code;

	if (is_ipv4) {
		icmp_header_data	= &misc3->icmpv4_header_data;
		icmp_type		= &misc3->icmpv4_type;
		icmp_code		= &misc3->icmpv4_code;
	} else {
		icmp_header_data	= &misc3->icmpv6_header_data;
		icmp_type		= &misc3->icmpv6_type;
		icmp_code		= &misc3->icmpv6_code;
	}

	DR_STE_SET(icmp_v1, tag, icmp_header_data, *icmp_header_data);
	DR_STE_SET(icmp_v1, tag, icmp_type, *icmp_type);
	DR_STE_SET(icmp_v1, tag, icmp_code, *icmp_code);

	*icmp_header_data = 0;
	*icmp_type = 0;
	*icmp_code = 0;

	return 0;
}

static void dr_ste_v1_build_icmp_init(struct dr_ste_build *sb,
				      struct dr_match_param *mask)
{
	dr_ste_v1_build_icmp_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_ETHL4_MISC_O;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_icmp_tag;
}

static int dr_ste_v1_build_general_purpose_tag(struct dr_match_param *value,
					       struct dr_ste_build *sb,
					       uint8_t *tag)
{
	struct dr_match_misc2 *misc2 = &value->misc2;

	DR_STE_SET_TAG(general_purpose, tag, general_purpose_lookup_field,
		       misc2, metadata_reg_a);

	return 0;
}

static void dr_ste_v1_build_general_purpose_init(struct dr_ste_build *sb,
						 struct dr_match_param *mask)
{
	dr_ste_v1_build_general_purpose_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_GENERAL_PURPOSE;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_general_purpose_tag;
}

static int dr_ste_v1_build_eth_l4_misc_tag(struct dr_match_param *value,
					   struct dr_ste_build *sb,
					   uint8_t *tag)
{
	struct dr_match_misc3 *misc3 = &value->misc3;

	if (sb->inner) {
		DR_STE_SET_TAG(eth_l4_misc_v1, tag, seq_num, misc3, inner_tcp_seq_num);
		DR_STE_SET_TAG(eth_l4_misc_v1, tag, ack_num, misc3, inner_tcp_ack_num);
	} else {
		DR_STE_SET_TAG(eth_l4_misc_v1, tag, seq_num, misc3, outer_tcp_seq_num);
		DR_STE_SET_TAG(eth_l4_misc_v1, tag, ack_num, misc3, outer_tcp_ack_num);
	}

	return 0;
}

static void dr_ste_v1_build_eth_l4_misc_init(struct dr_ste_build *sb,
					     struct dr_match_param *mask)
{
	dr_ste_v1_build_eth_l4_misc_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_ETHL4_MISC_O;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_eth_l4_misc_tag;
}

static int
dr_ste_v1_build_flex_parser_tnl_vxlan_gpe_tag(struct dr_match_param *value,
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
dr_ste_v1_build_flex_parser_tnl_vxlan_gpe_init(struct dr_ste_build *sb,
					       struct dr_match_param *mask)
{
	dr_ste_v1_build_flex_parser_tnl_vxlan_gpe_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_FLEX_PARSER_TNL_HEADER;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_flex_parser_tnl_vxlan_gpe_tag;
}

static int
dr_ste_v1_build_flex_parser_tnl_geneve_tag(struct dr_match_param *value,
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
dr_ste_v1_build_flex_parser_tnl_geneve_init(struct dr_ste_build *sb,
					    struct dr_match_param *mask)
{
	dr_ste_v1_build_flex_parser_tnl_geneve_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_FLEX_PARSER_TNL_HEADER;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_flex_parser_tnl_geneve_tag;
}

static int
dr_ste_v1_build_flex_parser_tnl_geneve_tlv_opt_tag(struct dr_match_param *value,
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
dr_ste_v1_build_flex_parser_tnl_geneve_tlv_opt_init(struct dr_ste_build *sb,
						    struct dr_match_param *mask)
{
	dr_ste_v1_build_flex_parser_tnl_geneve_tlv_opt_tag(mask, sb, sb->bit_mask);

	/* STEs with lookup type FLEX_PARSER_{0/1} includes
	 * flex parsers_{0-3}/{4-7} respectively.
	 */
	sb->lu_type = sb->caps->flex_parser_id_geneve_opt_0 <= DR_STE_MAX_FLEX_0_ID ?
		      DR_STE_V1_LU_TYPE_FLEX_PARSER_0 :
		      DR_STE_V1_LU_TYPE_FLEX_PARSER_1;

	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_flex_parser_tnl_geneve_tlv_opt_tag;
}

static int dr_ste_v1_build_flex_parser_tnl_gtpu_tag(struct dr_match_param *value,
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

static void dr_ste_v1_build_flex_parser_tnl_gtpu_init(struct dr_ste_build *sb,
						      struct dr_match_param *mask)
{
	dr_ste_v1_build_flex_parser_tnl_gtpu_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_FLEX_PARSER_TNL_HEADER;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_flex_parser_tnl_gtpu_tag;
}

static int
dr_ste_v1_build_tnl_gtpu_flex_parser_0_tag(struct dr_match_param *value,
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
dr_ste_v1_build_tnl_gtpu_flex_parser_0_init(struct dr_ste_build *sb,
					    struct dr_match_param *mask)
{
	dr_ste_v1_build_tnl_gtpu_flex_parser_0_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_FLEX_PARSER_0;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_tnl_gtpu_flex_parser_0_tag;
}

static int
dr_ste_v1_build_tnl_gtpu_flex_parser_1_tag(struct dr_match_param *value,
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
dr_ste_v1_build_tnl_gtpu_flex_parser_1_init(struct dr_ste_build *sb,
					    struct dr_match_param *mask)
{
	dr_ste_v1_build_tnl_gtpu_flex_parser_1_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_FLEX_PARSER_1;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_tnl_gtpu_flex_parser_1_tag;
}

static int dr_ste_v1_build_register_0_tag(struct dr_match_param *value,
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

static void dr_ste_v1_build_register_0_init(struct dr_ste_build *sb,
					    struct dr_match_param *mask)
{
	dr_ste_v1_build_register_0_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_STEERING_REGISTERS_0;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_register_0_tag;
}

static int dr_ste_v1_build_register_1_tag(struct dr_match_param *value,
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

static void dr_ste_v1_build_register_1_init(struct dr_ste_build *sb,
					    struct dr_match_param *mask)
{
	dr_ste_v1_build_register_1_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_STEERING_REGISTERS_1;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_register_1_tag;
}

static void dr_ste_v1_build_src_gvmi_qpn_bit_mask(struct dr_match_param *value,
						  uint8_t *bit_mask)
{
	struct dr_match_misc *misc_mask = &value->misc;

	DR_STE_SET_ONES(src_gvmi_qp_v1, bit_mask, source_gvmi, misc_mask, source_port);
	DR_STE_SET_ONES(src_gvmi_qp_v1, bit_mask, source_qp, misc_mask, source_sqn);
}

static int dr_ste_v1_build_src_gvmi_qpn_tag(struct dr_match_param *value,
					    struct dr_ste_build *sb,
					    uint8_t *tag)
{
	struct dr_match_misc *misc = &value->misc;
	struct dr_devx_vport_cap *vport_cap;
	uint8_t *bit_mask = sb->bit_mask;
	bool source_gvmi_set;

	DR_STE_SET_TAG(src_gvmi_qp_v1, tag, source_qp, misc, source_sqn);

	source_gvmi_set = DR_STE_GET(src_gvmi_qp_v1, bit_mask, source_gvmi);
	if (source_gvmi_set) {
		vport_cap = dr_get_vport_cap(sb->caps, misc->source_port);
		if (!vport_cap)
			return errno;

		if (vport_cap->gvmi)
			DR_STE_SET(src_gvmi_qp_v1, tag, source_gvmi, vport_cap->gvmi);

		misc->source_port = 0;
	}

	return 0;
}

static void dr_ste_v1_build_src_gvmi_qpn_init(struct dr_ste_build *sb,
					      struct dr_match_param *mask)
{
	dr_ste_v1_build_src_gvmi_qpn_bit_mask(mask, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_SRC_QP_GVMI;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_src_gvmi_qpn_tag;
}

static void dr_ste_set_flex_parser(uint32_t *misc4_field_id,
				   uint32_t *misc4_field_value,
				   bool *parser_is_used,
				   uint8_t *tag)
{
	uint32_t id = *misc4_field_id;
	uint8_t *parser_ptr;

	if (parser_is_used[id])
		return;

	parser_is_used[id] = true;
	parser_ptr = dr_ste_calc_flex_parser_offset(tag, id);

	*(__be32 *)parser_ptr = htobe32(*misc4_field_value);
	*misc4_field_id = 0;
	*misc4_field_value = 0;
}

static int dr_ste_v1_build_felx_parser_tag(struct dr_match_param *value,
					   struct dr_ste_build *sb,
					   uint8_t *tag)
{
	struct dr_match_misc4 *misc_4_mask = &value->misc4;
	bool parser_is_used[NUM_OF_FLEX_PARSERS] = {};

	dr_ste_set_flex_parser(&misc_4_mask->prog_sample_field_id_0,
			       &misc_4_mask->prog_sample_field_value_0,
			       parser_is_used, tag);

	dr_ste_set_flex_parser(&misc_4_mask->prog_sample_field_id_1,
			       &misc_4_mask->prog_sample_field_value_1,
			       parser_is_used, tag);

	dr_ste_set_flex_parser(&misc_4_mask->prog_sample_field_id_2,
			       &misc_4_mask->prog_sample_field_value_2,
			       parser_is_used, tag);

	dr_ste_set_flex_parser(&misc_4_mask->prog_sample_field_id_3,
			       &misc_4_mask->prog_sample_field_value_3,
			       parser_is_used, tag);

	return 0;
}

static void dr_ste_v1_build_flex_parser_0_init(struct dr_ste_build *sb,
					       struct dr_match_param *mask)
{
	sb->lu_type = DR_STE_V1_LU_TYPE_FLEX_PARSER_0;
	dr_ste_v1_build_felx_parser_tag(mask, sb, sb->bit_mask);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_felx_parser_tag;
}

static void dr_ste_v1_build_flex_parser_1_init(struct dr_ste_build *sb,
					       struct dr_match_param *mask)
{
	sb->lu_type = DR_STE_V1_LU_TYPE_FLEX_PARSER_1;
	dr_ste_v1_build_felx_parser_tag(mask, sb, sb->bit_mask);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_felx_parser_tag;
}

static struct dr_ste_ctx ste_ctx_v1 = {
	/* Builders */
	.build_eth_l2_src_dst_init	= &dr_ste_v1_build_eth_l2_src_dst_init,
	.build_eth_l3_ipv6_src_init	= &dr_ste_v1_build_eth_l3_ipv6_src_init,
	.build_eth_l3_ipv6_dst_init	= &dr_ste_v1_build_eth_l3_ipv6_dst_init,
	.build_eth_l3_ipv4_5_tuple_init	= &dr_ste_v1_build_eth_l3_ipv4_5_tuple_init,
	.build_eth_l2_src_init		= &dr_ste_v1_build_eth_l2_src_init,
	.build_eth_l2_dst_init		= &dr_ste_v1_build_eth_l2_dst_init,
	.build_eth_l2_tnl_init		= &dr_ste_v1_build_eth_l2_tnl_init,
	.build_eth_l3_ipv4_misc_init	= &dr_ste_v1_build_eth_l3_ipv4_misc_init,
	.build_eth_ipv6_l3_l4_init	= &dr_ste_v1_build_eth_ipv6_l3_l4_init,
	.build_mpls_init		= &dr_ste_v1_build_mpls_init,
	.build_tnl_gre_init		= &dr_ste_v1_build_tnl_gre_init,
	.build_tnl_mpls_over_udp_init	= &dr_ste_v1_build_tnl_mpls_over_udp_init,
	.build_tnl_mpls_over_gre_init	= &dr_ste_v1_build_tnl_mpls_over_gre_init,
	.build_icmp_init		= &dr_ste_v1_build_icmp_init,
	.build_general_purpose_init	= &dr_ste_v1_build_general_purpose_init,
	.build_eth_l4_misc_init		= &dr_ste_v1_build_eth_l4_misc_init,
	.build_tnl_vxlan_gpe_init	= &dr_ste_v1_build_flex_parser_tnl_vxlan_gpe_init,
	.build_tnl_geneve_init		= &dr_ste_v1_build_flex_parser_tnl_geneve_init,
	.build_tnl_geneve_tlv_opt_init	= &dr_ste_v1_build_flex_parser_tnl_geneve_tlv_opt_init,
	.build_tnl_gtpu_init		= &dr_ste_v1_build_flex_parser_tnl_gtpu_init,
	.build_tnl_gtpu_flex_parser_0	= &dr_ste_v1_build_tnl_gtpu_flex_parser_0_init,
	.build_tnl_gtpu_flex_parser_1	= &dr_ste_v1_build_tnl_gtpu_flex_parser_1_init,
	.build_register_0_init		= &dr_ste_v1_build_register_0_init,
	.build_register_1_init		= &dr_ste_v1_build_register_1_init,
	.build_src_gvmi_qpn_init	= &dr_ste_v1_build_src_gvmi_qpn_init,
	.build_flex_parser_0_init	= &dr_ste_v1_build_flex_parser_0_init,
	.build_flex_parser_1_init	= &dr_ste_v1_build_flex_parser_1_init,
	/* Getters and Setters */
	.ste_init			= &dr_ste_v1_init,
	.set_next_lu_type		= &dr_ste_v1_set_next_lu_type,
	.get_next_lu_type		= &dr_ste_v1_get_next_lu_type,
	.set_miss_addr			= &dr_ste_v1_set_miss_addr,
	.get_miss_addr			= &dr_ste_v1_get_miss_addr,
	.set_hit_addr			= &dr_ste_v1_set_hit_addr,
	.set_byte_mask			= &dr_ste_v1_set_byte_mask,
	.get_byte_mask			= &dr_ste_v1_get_byte_mask,
	/* Actions */
	.actions_caps			= DR_STE_CTX_ACTION_CAP_TX_POP |
					  DR_STE_CTX_ACTION_CAP_RX_PUSH,
	.set_actions_rx			= &dr_ste_v1_set_actions_rx,
	.set_actions_tx			= &dr_ste_v1_set_actions_tx,
	.set_action_set			= &dr_ste_v1_set_action_set,
	.set_action_add			= &dr_ste_v1_set_action_add,
	.set_action_copy		= &dr_ste_v1_set_action_copy,
	.get_action_hw_field		= &dr_ste_v1_get_action_hw_field,
	.set_action_decap_l3_list	= &dr_ste_v1_set_action_decap_l3_list,
	/* Send */
	.prepare_for_postsend		= &dr_ste_v1_prepare_for_postsend,
};

struct dr_ste_ctx *dr_ste_get_ctx_v1(void)
{
	return &ste_ctx_v1;
}
