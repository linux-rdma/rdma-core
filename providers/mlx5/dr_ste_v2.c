/*
 * Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

enum {
	DR_STE_V2_ACTION_MDFY_FLD_L2_OUT_0		= 0x00,
	DR_STE_V2_ACTION_MDFY_FLD_L2_OUT_1		= 0x01,
	DR_STE_V2_ACTION_MDFY_FLD_L2_OUT_2		= 0x02,
	DR_STE_V2_ACTION_MDFY_FLD_SRC_L2_OUT_0		= 0x08,
	DR_STE_V2_ACTION_MDFY_FLD_SRC_L2_OUT_1		= 0x09,
	DR_STE_V2_ACTION_MDFY_FLD_L3_OUT_0		= 0x0e,
	DR_STE_V2_ACTION_MDFY_FLD_L4_OUT_0		= 0x18,
	DR_STE_V2_ACTION_MDFY_FLD_L4_OUT_1		= 0x19,
	DR_STE_V2_ACTION_MDFY_FLD_IPV4_OUT_0		= 0x40,
	DR_STE_V2_ACTION_MDFY_FLD_IPV4_OUT_1		= 0x41,
	DR_STE_V2_ACTION_MDFY_FLD_IPV6_DST_OUT_0	= 0x44,
	DR_STE_V2_ACTION_MDFY_FLD_IPV6_DST_OUT_1	= 0x45,
	DR_STE_V2_ACTION_MDFY_FLD_IPV6_DST_OUT_2	= 0x46,
	DR_STE_V2_ACTION_MDFY_FLD_IPV6_DST_OUT_3	= 0x47,
	DR_STE_V2_ACTION_MDFY_FLD_IPV6_SRC_OUT_0	= 0x4c,
	DR_STE_V2_ACTION_MDFY_FLD_IPV6_SRC_OUT_1	= 0x4d,
	DR_STE_V2_ACTION_MDFY_FLD_IPV6_SRC_OUT_2	= 0x4e,
	DR_STE_V2_ACTION_MDFY_FLD_IPV6_SRC_OUT_3	= 0x4f,
	DR_STE_V2_ACTION_MDFY_FLD_TCP_MISC_0		= 0x5e,
	DR_STE_V2_ACTION_MDFY_FLD_TCP_MISC_1		= 0x5f,
	DR_STE_V2_ACTION_MDFY_FLD_METADATA_2_CQE	= 0x7b,
	DR_STE_V2_ACTION_MDFY_FLD_GNRL_PURPOSE		= 0x7c,
	DR_STE_V2_ACTION_MDFY_FLD_FLEX_PARSER_7		= 0x82,
	DR_STE_V2_ACTION_MDFY_FLD_FLEX_PARSER_6		= 0x83,
	DR_STE_V2_ACTION_MDFY_FLD_FLEX_PARSER_5		= 0x84,
	DR_STE_V2_ACTION_MDFY_FLD_FLEX_PARSER_4		= 0x85,
	DR_STE_V2_ACTION_MDFY_FLD_FLEX_PARSER_3		= 0x86,
	DR_STE_V2_ACTION_MDFY_FLD_FLEX_PARSER_2		= 0x87,
	DR_STE_V2_ACTION_MDFY_FLD_FLEX_PARSER_1		= 0x88,
	DR_STE_V2_ACTION_MDFY_FLD_FLEX_PARSER_0		= 0x89,
	DR_STE_V2_ACTION_MDFY_FLD_REGISTER_2_0		= 0x90,
	DR_STE_V2_ACTION_MDFY_FLD_REGISTER_2_1		= 0x91,
	DR_STE_V2_ACTION_MDFY_FLD_REGISTER_1_0		= 0x92,
	DR_STE_V2_ACTION_MDFY_FLD_REGISTER_1_1		= 0x93,
	DR_STE_V2_ACTION_MDFY_FLD_REGISTER_0_0		= 0x94,
	DR_STE_V2_ACTION_MDFY_FLD_REGISTER_0_1		= 0x95,
};

static const struct dr_ste_action_modify_field dr_ste_v2_action_modify_field_arr[] = {
	[MLX5_ACTION_IN_FIELD_OUT_SMAC_47_16] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_SRC_L2_OUT_0, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SMAC_15_0] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_SRC_L2_OUT_1, .start = 16, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_ETHERTYPE] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_L2_OUT_1, .start = 0, .end = 15,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DMAC_47_16] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_L2_OUT_0, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DMAC_15_0] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_L2_OUT_1, .start = 16, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_IP_DSCP] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_L3_OUT_0, .start = 18, .end = 23,
	},
	[MLX5_ACTION_IN_FIELD_OUT_IP_ECN] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_L3_OUT_0, .start = 16, .end = 17,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_FLAGS] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_L4_OUT_1, .start = 16, .end = 24,
		.l4_type = DR_STE_ACTION_MDFY_TYPE_L4_TCP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_SPORT] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_L4_OUT_0, .start = 16, .end = 31,
		.l4_type = DR_STE_ACTION_MDFY_TYPE_L4_TCP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_DPORT] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_L4_OUT_0, .start = 0, .end = 15,
		.l4_type = DR_STE_ACTION_MDFY_TYPE_L4_TCP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_IP_TTL] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_L3_OUT_0, .start = 8, .end = 15,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV4,
	},
	[MLX5_ACTION_IN_FIELD_OUT_IPV6_HOPLIMIT] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_L3_OUT_0, .start = 8, .end = 15,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_UDP_SPORT] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_L4_OUT_0, .start = 16, .end = 31,
		.l4_type = DR_STE_ACTION_MDFY_TYPE_L4_UDP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_UDP_DPORT] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_L4_OUT_0, .start = 0, .end = 15,
		.l4_type = DR_STE_ACTION_MDFY_TYPE_L4_UDP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV6_127_96] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_IPV6_SRC_OUT_0, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV6_95_64] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_IPV6_SRC_OUT_1, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV6_63_32] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_IPV6_SRC_OUT_2, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV6_31_0] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_IPV6_SRC_OUT_3, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV6_127_96] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_IPV6_DST_OUT_0, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV6_95_64] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_IPV6_DST_OUT_1, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV6_63_32] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_IPV6_DST_OUT_2, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV6_31_0] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_IPV6_DST_OUT_3, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV4] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_IPV4_OUT_0, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV4,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV4] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_IPV4_OUT_1, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV4,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGA] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_GNRL_PURPOSE, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGB] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_METADATA_2_CQE, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_0] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_REGISTER_0_0, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_1] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_REGISTER_0_1, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_2] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_REGISTER_1_0, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_3] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_REGISTER_1_1, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_4] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_REGISTER_2_0, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_5] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_REGISTER_2_1, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_SEQ_NUM] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_TCP_MISC_0, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_ACK_NUM] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_TCP_MISC_1, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_FIRST_VID] = {
		.hw_field = DR_STE_V2_ACTION_MDFY_FLD_L2_OUT_2, .start = 0, .end = 15,
	},
	[MLX5_ACTION_IN_FIELD_OUT_GTPU_TEID] = {
		.flags = DR_STE_ACTION_MODIFY_FLAG_REQ_FLEX, .start = 0, .end = 31,
	},
};

static struct dr_ste_ctx ste_ctx_v2;
static pthread_mutex_t ctx_mutex = PTHREAD_MUTEX_INITIALIZER;

struct dr_ste_ctx *dr_ste_get_ctx_v2(void)
{
	pthread_mutex_lock(&ctx_mutex);

	if (!ste_ctx_v2.actions_caps) {
		ste_ctx_v2 = *dr_ste_get_ctx_v1();
		ste_ctx_v2.actions_caps = DR_STE_CTX_ACTION_CAP_TX_POP |
					  DR_STE_CTX_ACTION_CAP_RX_PUSH |
					  DR_STE_CTX_ACTION_CAP_RX_ENCAP |
					  DR_STE_CTX_ACTION_CAP_MODIFY_HDR_INLINE;
		ste_ctx_v2.action_modify_field_arr = dr_ste_v2_action_modify_field_arr;
		ste_ctx_v2.action_modify_field_arr_size = ARRAY_SIZE(dr_ste_v2_action_modify_field_arr);
	}

	pthread_mutex_unlock(&ctx_mutex);

	return &ste_ctx_v2;
}
