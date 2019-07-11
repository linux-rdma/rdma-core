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

#include <unistd.h>
#include <arpa/inet.h>
#include <ccan/array_size.h>
#include "mlx5dv_dr.h"

enum dr_action_domain {
	DR_ACTION_DOMAIN_NIC_INGRESS,
	DR_ACTION_DOMAIN_NIC_EGRESS,
	DR_ACTION_DOMAIN_FDB_INGRESS,
	DR_ACTION_DOMAIN_FDB_EGRESS,
	DR_ACTION_DOMAIN_MAX,
};

enum dr_action_valid_state {
	DR_ACTION_STATE_ERR,
	DR_ACTION_STATE_NO_ACTION,
	DR_ACTION_STATE_REFORMAT,
	DR_ACTION_STATE_MODIFY_HDR,
	DR_ACTION_STATE_NON_TERM,
	DR_ACTION_STATE_TERM,
	DR_ACTION_STATE_MAX,
};

static const enum dr_action_valid_state next_action_state[DR_ACTION_DOMAIN_MAX]
							 [DR_ACTION_STATE_MAX]
							 [DR_ACTION_TYP_MAX] = {
	[DR_ACTION_DOMAIN_NIC_INGRESS] = {
		[DR_ACTION_STATE_NO_ACTION] = {
			[DR_ACTION_TYP_DROP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_QP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_TAG]		= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_TNL_L2_TO_L2]	= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_TNL_L3_TO_L2]	= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
		},
		[DR_ACTION_STATE_REFORMAT] = {
			[DR_ACTION_TYP_QP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_TAG]		= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
		},
		[DR_ACTION_STATE_MODIFY_HDR] = {
			[DR_ACTION_TYP_QP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_TAG]		= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_MODIFY_HDR,
		},
		[DR_ACTION_STATE_NON_TERM] = {
			[DR_ACTION_TYP_DROP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_QP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_TAG]		= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_TNL_L2_TO_L2]	= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_TNL_L3_TO_L2]	= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
		},
		[DR_ACTION_STATE_TERM] = {
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_TERM,
		},
	},
	[DR_ACTION_DOMAIN_NIC_EGRESS] = {
		[DR_ACTION_STATE_NO_ACTION] = {
			[DR_ACTION_TYP_DROP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_L2_TO_TNL_L2]	= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_L2_TO_TNL_L3]	= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
		},
		[DR_ACTION_STATE_REFORMAT] = {
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_REFORMAT,
		},
		[DR_ACTION_STATE_MODIFY_HDR] = {
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_L2_TO_TNL_L2]	= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_L2_TO_TNL_L3]	= DR_ACTION_STATE_REFORMAT,
		},
		[DR_ACTION_STATE_NON_TERM] = {
			[DR_ACTION_TYP_DROP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_L2_TO_TNL_L2]	= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_L2_TO_TNL_L3]	= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
		},
		[DR_ACTION_STATE_TERM] = {
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_TERM,
		},
	},
	[DR_ACTION_DOMAIN_FDB_INGRESS] = {
		[DR_ACTION_STATE_NO_ACTION] = {
			[DR_ACTION_TYP_DROP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_TNL_L2_TO_L2]	= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_TNL_L3_TO_L2]	= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_VPORT]		= DR_ACTION_STATE_TERM,
		},
		[DR_ACTION_STATE_REFORMAT] = {
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_VPORT]		= DR_ACTION_STATE_TERM,
		},
		[DR_ACTION_STATE_MODIFY_HDR] = {
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_VPORT]		= DR_ACTION_STATE_TERM,
		},
		[DR_ACTION_STATE_NON_TERM] = {
			[DR_ACTION_TYP_DROP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_TNL_L2_TO_L2]	= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_TNL_L3_TO_L2]	= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_VPORT]		= DR_ACTION_STATE_TERM,
		},
		[DR_ACTION_STATE_TERM] = {
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_TERM,
		},
	},
	[DR_ACTION_DOMAIN_FDB_EGRESS] = {
		[DR_ACTION_STATE_NO_ACTION] = {
			[DR_ACTION_TYP_DROP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_L2_TO_TNL_L2]	= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_L2_TO_TNL_L3]	= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_VPORT]		= DR_ACTION_STATE_TERM,
		},
		[DR_ACTION_STATE_REFORMAT] = {
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_VPORT]		= DR_ACTION_STATE_TERM,
		},
		[DR_ACTION_STATE_MODIFY_HDR] = {
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_L2_TO_TNL_L2]	= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_L2_TO_TNL_L3]	= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_VPORT]		= DR_ACTION_STATE_TERM,
		},
		[DR_ACTION_STATE_NON_TERM] = {
			[DR_ACTION_TYP_DROP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_L2_TO_TNL_L2]	= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_L2_TO_TNL_L3]	= DR_ACTION_STATE_REFORMAT,
			[DR_ACTION_TYP_VPORT]		= DR_ACTION_STATE_TERM,
		},
		[DR_ACTION_STATE_TERM] = {
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_TERM,
		},
	},
};

struct dr_action_modify_field_conv {
	uint16_t hw_field;
	uint8_t start;
	uint8_t end;
	uint8_t l3_type;
	uint8_t l4_type;
};

static const struct dr_action_modify_field_conv dr_action_conv_arr[] = {
	[MLX5_ACTION_IN_FIELD_OUT_SMAC_47_16] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L2_1, .start = 16, .end = 47,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SMAC_15_0] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L2_1, .start = 0, .end = 15,
	},
	[MLX5_ACTION_IN_FIELD_OUT_ETHERTYPE] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L2_2, .start = 32, .end = 47,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DMAC_47_16] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L2_0, .start = 16, .end = 47,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DMAC_15_0] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L2_0, .start = 0, .end = 15,
	},
	[MLX5_ACTION_IN_FIELD_OUT_IP_DSCP] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L3_1, .start = 0, .end = 5,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_FLAGS] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L4_0, .start = 48, .end = 56,
		.l4_type = MLX5_DR_ACTION_MDFY_HW_HDR_L4_TCP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_SPORT] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L4_0, .start = 0, .end = 15,
		.l4_type = MLX5_DR_ACTION_MDFY_HW_HDR_L4_TCP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_DPORT] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L4_0, .start = 16, .end = 31,
		.l4_type = MLX5_DR_ACTION_MDFY_HW_HDR_L4_TCP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_IP_TTL] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L3_1, .start = 8, .end = 15,
		.l3_type = MLX5_DR_ACTION_MDFY_HW_HDR_L3_IPV4,
	},
	[MLX5_ACTION_IN_FIELD_OUT_IPV6_HOPLIMIT] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L3_1, .start = 8, .end = 15,
		.l3_type = MLX5_DR_ACTION_MDFY_HW_HDR_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_UDP_SPORT] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L4_0, .start = 0, .end = 15,
		.l4_type = MLX5_DR_ACTION_MDFY_HW_HDR_L4_UDP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_UDP_DPORT] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L4_0, .start = 16, .end = 31,
		.l4_type = MLX5_DR_ACTION_MDFY_HW_HDR_L4_UDP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV6_127_96] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L3_3, .start = 32, .end = 63,
		.l3_type = MLX5_DR_ACTION_MDFY_HW_HDR_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV6_95_64] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L3_3, .start = 0, .end = 31,
		.l3_type = MLX5_DR_ACTION_MDFY_HW_HDR_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV6_63_32] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L3_4, .start = 32, .end = 63,
		.l3_type = MLX5_DR_ACTION_MDFY_HW_HDR_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV6_31_0] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L3_4, .start = 0, .end = 31,
		.l3_type = MLX5_DR_ACTION_MDFY_HW_HDR_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV6_127_96] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L3_0, .start = 32, .end = 63,
		.l3_type = MLX5_DR_ACTION_MDFY_HW_HDR_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV6_95_64] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L3_0, .start = 0, .end = 31,
		.l3_type = MLX5_DR_ACTION_MDFY_HW_HDR_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV6_63_32] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L3_2, .start = 32, .end = 63,
		.l3_type = MLX5_DR_ACTION_MDFY_HW_HDR_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV6_31_0] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L3_2, .start = 0, .end = 31,
		.l3_type = MLX5_DR_ACTION_MDFY_HW_HDR_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV4] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L3_0, .start = 0, .end = 31,
		.l3_type = MLX5_DR_ACTION_MDFY_HW_HDR_L3_IPV4,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV4] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L3_0, .start = 32, .end = 63,
		.l3_type = MLX5_DR_ACTION_MDFY_HW_HDR_L3_IPV4,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGA] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_METADATA, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGB] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_METADATA, .start = 32, .end = 63,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_0] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_REG_0, .start = 32, .end = 63,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_1] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_REG_0, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_2] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_REG_1, .start = 32, .end = 63,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_3] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_REG_1, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_4] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_REG_2, .start = 32, .end = 63,
	},
	[MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_5] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_REG_2, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_SEQ_NUM] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L4_1, .start = 32, .end = 63,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_ACK_NUM] = {
		.hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_L4_1, .start = 0, .end = 31,
	},
};

struct dr_action_apply_attr {
	uint32_t	modify_index;
	uint16_t	modify_actions;
	uint32_t	decap_index;
	uint16_t	decap_actions;
	bool		decap_with_vlan;
	uint64_t	final_icm_addr;
	uint32_t	flow_tag;
	uint32_t	ctr_id;
	uint16_t	gvmi;
	uint32_t	reformat_id;
	uint32_t	reformat_size;
};

static enum mlx5dv_flow_action_packet_reformat_type
dr_action_type_to_reformat_enum(enum dr_action_type action_type)
{
	switch (action_type) {
	case DR_ACTION_TYP_TNL_L2_TO_L2:
		return MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TUNNEL_TO_L2;
	case DR_ACTION_TYP_L2_TO_TNL_L2:
		return MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L2_TUNNEL;
	case DR_ACTION_TYP_TNL_L3_TO_L2:
		return MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L3_TUNNEL_TO_L2;
	case DR_ACTION_TYP_L2_TO_TNL_L3:
		return MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L3_TUNNEL;
	default:
		assert(false);
		return 0;
	}
}

static enum dr_action_type
dr_action_reformat_to_action_type(enum mlx5dv_flow_action_packet_reformat_type type)
{
	switch (type) {
	case MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TUNNEL_TO_L2:
		return DR_ACTION_TYP_TNL_L2_TO_L2;
	case MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L2_TUNNEL:
		return DR_ACTION_TYP_L2_TO_TNL_L2;
	case MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L3_TUNNEL_TO_L2:
		return DR_ACTION_TYP_TNL_L3_TO_L2;
	case MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L3_TUNNEL:
		return DR_ACTION_TYP_L2_TO_TNL_L3;
	default:
		assert(false);
		return 0;
	}
}

static inline void dr_actions_init_next_ste(uint8_t **last_ste,
					    uint32_t *added_stes,
					    enum dr_ste_entry_type entry_type,
					    uint16_t gvmi)
{
	(*added_stes)++;
	*last_ste += DR_STE_SIZE;
	dr_ste_init(*last_ste, DR_STE_LU_TYPE_DONT_CARE, entry_type, gvmi);
}

static void dr_actions_apply_tx(uint8_t *action_type_set,
				uint8_t *last_ste,
				struct dr_action_apply_attr *attr,
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
			dr_actions_init_next_ste(&last_ste,
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
}

static void dr_actions_apply_rx(uint8_t *action_type_set,
				uint8_t *last_ste,
				struct dr_action_apply_attr *attr,
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
			dr_actions_init_next_ste(&last_ste,
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
			dr_actions_init_next_ste(&last_ste,
						 added_stes,
						 DR_STE_TYPE_RX,
						 attr->gvmi);

		dr_ste_rx_set_flow_tag(last_ste, attr->flow_tag);
	}
}

/* Apply the actions on the rule STE array starting from the last_ste.
 * Actions might require more than one STE, new_num_stes will return
 * the new size of the STEs array, rule with actions. */
static void dr_actions_apply(enum dr_ste_entry_type ste_type,
			     uint8_t *action_type_set,
			     uint8_t *last_ste,
			     struct dr_action_apply_attr *attr,
			     uint32_t *new_num_stes)
{
	uint32_t added_stes = 0;

	if (ste_type == DR_STE_TYPE_RX)
		dr_actions_apply_rx(action_type_set, last_ste, attr, &added_stes);
	else
		dr_actions_apply_tx(action_type_set, last_ste, attr, &added_stes);

	last_ste += added_stes * DR_STE_SIZE;
	*new_num_stes += added_stes;

	dr_ste_set_hit_addr(last_ste, attr->final_icm_addr, 1);
}

static enum dr_action_domain
dr_action_get_action_domain(enum mlx5dv_dr_domain_type domain,
			    enum dr_ste_entry_type ste_type)
{
	if (domain == MLX5DV_DR_DOMAIN_TYPE_NIC_RX) {
		return DR_ACTION_DOMAIN_NIC_INGRESS;
	} else if (domain == MLX5DV_DR_DOMAIN_TYPE_NIC_TX) {
		return DR_ACTION_DOMAIN_NIC_EGRESS;
	} else {
		/* FDB domain */
		if (ste_type == DR_STE_TYPE_RX)
			return DR_ACTION_DOMAIN_FDB_INGRESS;
		else
			return DR_ACTION_DOMAIN_FDB_EGRESS;
	}
}

static inline
int dr_action_validate_and_get_next_state(enum dr_action_domain action_domain,
					  uint32_t action_type,
					  uint32_t *state)
{
	uint32_t cur_state = *state;

	/* Check action state machine is valid */
	*state = next_action_state[action_domain][cur_state][action_type];

	if (*state == DR_ACTION_STATE_ERR) {
		errno = EOPNOTSUPP;
		return errno;
	}

	return 0;
}

#define WITH_VLAN_NUM_HW_ACTIONS 6

int dr_actions_build_ste_arr(struct mlx5dv_dr_matcher *matcher,
			     struct dr_matcher_rx_tx *nic_matcher,
			     struct mlx5dv_dr_action *actions[],
			     uint32_t num_actions,
			     uint8_t *ste_arr,
			     uint32_t *new_hw_ste_arr_sz)
{
	struct dr_domain_rx_tx *nic_dmn = nic_matcher->nic_tbl->nic_dmn;
	bool rx_rule = nic_dmn->ste_type == DR_STE_TYPE_RX;
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	uint8_t action_type_set[DR_ACTION_TYP_MAX] = {};
	uint32_t state = DR_ACTION_STATE_NO_ACTION;
	struct dr_action_apply_attr attr = {};
	enum dr_action_domain action_domain;
	uint8_t *last_ste;
	int i;

	attr.gvmi = dmn->info.caps.gvmi;
	attr.final_icm_addr = nic_dmn->default_icm_addr;
	action_domain = dr_action_get_action_domain(dmn->type, nic_dmn->ste_type);

	for (i = 0; i < num_actions; i++) {
		struct mlx5dv_dr_action *action;
		uint32_t action_type;

		action = actions[i];
		action_type = action->action_type;

		switch (action_type) {
		case DR_ACTION_TYP_DROP:
			attr.final_icm_addr = nic_dmn->drop_icm_addr;
			break;
		case DR_ACTION_TYP_FT:
			if (action->dest_tbl->dmn != dmn) {
				dr_dbg(dmn, "Destination table belongs to a different domain\n");
				goto out_invalid_arg;
			}
			if (action->dest_tbl->level <= matcher->tbl->level) {
				dr_dbg(dmn, "Destination table level should be higher than source table\n");
				goto out_invalid_arg;
			}
			attr.final_icm_addr = rx_rule ?
				action->dest_tbl->rx.s_anchor->chunk->icm_addr :
				action->dest_tbl->tx.s_anchor->chunk->icm_addr;
			break;
		case DR_ACTION_TYP_QP:
			{
				struct mlx5_qp *mlx5_qp = to_mqp(action->qp);

				if (!mlx5_qp->tir_icm_addr) {
					dr_dbg(dmn, "Unsupported QP for action\n");
					goto out_invalid_arg;
				}
				attr.final_icm_addr = mlx5_qp->tir_icm_addr;
			}
			break;
		case DR_ACTION_TYP_CTR:
			attr.ctr_id = action->ctr.devx_obj->object_id +
				action->ctr.offeset;
			break;
		case DR_ACTION_TYP_TAG:
			attr.flow_tag = action->flow_tag;
			break;
		case DR_ACTION_TYP_TNL_L2_TO_L2:
			break;
		case DR_ACTION_TYP_TNL_L3_TO_L2:
			if (action->rewrite.is_root_level) {
				dr_dbg(dmn, "Root decap L3 action cannot be used on current table\n");
				goto out_invalid_arg;
			}
			attr.decap_index = action->rewrite.index;
			attr.decap_actions = action->rewrite.num_of_actions;
			attr.decap_with_vlan =
				attr.decap_actions == WITH_VLAN_NUM_HW_ACTIONS;
			break;
		case DR_ACTION_TYP_MODIFY_HDR:
			if (action->rewrite.is_root_level) {
				dr_dbg(dmn, "Root modify header action cannot be used on current table\n");
				goto out_invalid_arg;
			}
			attr.modify_index = action->rewrite.index;
			attr.modify_actions = action->rewrite.num_of_actions;
			break;
		case DR_ACTION_TYP_L2_TO_TNL_L2:
		case DR_ACTION_TYP_L2_TO_TNL_L3:
			if (action->reformat.is_root_level) {
				dr_dbg(dmn, "Root encap action cannot be used on current table\n");
				goto out_invalid_arg;
			}
			attr.reformat_size = action->reformat.reformat_size;
			attr.reformat_id = action->reformat.dvo->object_id;
			break;
		case DR_ACTION_TYP_VPORT:
			if (action->vport.dmn != dmn) {
				dr_dbg(dmn, "Destination vport belongs to a different domain\n");
				goto out_invalid_arg;
			}
			if (rx_rule) {
				/* Loopback on WIRE vport is not supported */
				if (action->vport.num == WIRE_PORT)
					goto out_invalid_arg;

				attr.final_icm_addr = action->vport.caps->icm_address_rx;
			} else {
				attr.final_icm_addr = action->vport.caps->icm_address_tx;
			}
			break;
		default:
			goto out_invalid_arg;
		}

		/* Check action duplication */
		if (++action_type_set[action_type] > 1) {
			dr_dbg(dmn, "Duplicate action type provided\n");
			goto out_invalid_arg;
		}

		/* Check action state machine is valid */
		if (dr_action_validate_and_get_next_state(action_domain,
							  action_type,
							  &state)) {
			dr_dbg(dmn, "Invalid action sequence provided\n");
			goto out_errno;
		}
	}

	*new_hw_ste_arr_sz = nic_matcher->num_of_builders;
	last_ste = ste_arr + DR_STE_SIZE * (nic_matcher->num_of_builders - 1);

	dr_actions_apply(nic_dmn->ste_type,
			 action_type_set,
			 last_ste,
			 &attr,
			 new_hw_ste_arr_sz);

	return 0;

out_invalid_arg:
	errno = EINVAL;
out_errno:
	return errno;
}

int dr_actions_build_attr(struct mlx5dv_dr_matcher *matcher,
			  struct mlx5dv_dr_action *actions[],
			  size_t num_actions,
			  struct mlx5dv_flow_action_attr *attr)
{
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	int i;

	for (i = 0; i < num_actions; i++) {
		switch (actions[i]->action_type) {
		case DR_ACTION_TYP_FT:
			if (actions[i]->dest_tbl->dmn != dmn) {
				dr_dbg(dmn, "Destination table belongs to a different domain\n");
				errno = EINVAL;
				return errno;
			}
			attr[i].type = MLX5DV_FLOW_ACTION_DEST_DEVX;
			attr[i].obj = actions[i]->dest_tbl->devx_obj;
			break;
		case DR_ACTION_TYP_TNL_L2_TO_L2:
		case DR_ACTION_TYP_L2_TO_TNL_L2:
		case DR_ACTION_TYP_TNL_L3_TO_L2:
		case DR_ACTION_TYP_L2_TO_TNL_L3:
			attr[i].type = MLX5DV_FLOW_ACTION_IBV_FLOW_ACTION;
			attr[i].action = actions[i]->reformat.flow_action;
			break;
		case DR_ACTION_TYP_MODIFY_HDR:
			attr[i].type = MLX5DV_FLOW_ACTION_IBV_FLOW_ACTION;
			attr[i].action = actions[i]->rewrite.flow_action;
			break;
		case DR_ACTION_TYP_QP:
			attr[i].type = MLX5DV_FLOW_ACTION_DEST_IBV_QP;
			attr[i].qp = actions[i]->qp;
			break;
		case DR_ACTION_TYP_CTR:
			attr[i].type = MLX5DV_FLOW_ACTION_COUNTERS_DEVX;
			attr[i].obj = actions[i]->ctr.devx_obj;
			break;
		case DR_ACTION_TYP_TAG:
			attr[i].type = MLX5DV_FLOW_ACTION_TAG;
			attr[i].tag_value = actions[i]->flow_tag;
			break;
		default:
			dr_dbg(dmn, "Found unsupported action type: %d\n",
			       actions[i]->action_type);
			errno = ENOTSUP;
			return errno;
		}
	}
	return 0;
}

#define SVLAN_ETHERTYPE 0x88a8
#define HDR_LEN_L2_ONLY 14
#define HDR_LEN_L2_VLAN 18
#define REWRITE_HW_ACTION_NUM 6

static int dr_actions_l2_rewrite(struct mlx5dv_dr_domain *dmn,
				 struct mlx5dv_dr_action *action,
				 void *data, size_t data_sz)
{
	struct mlx5_ifc_l2_hdr_bits *l2_hdr = data;
	uint64_t ops[REWRITE_HW_ACTION_NUM] = {};
	uint32_t hdr_fld_4b;
	uint16_t hdr_fld_2b;
	uint16_t vlan_type;
	bool vlan;
	int i = 0;
	int ret;

	vlan = (data_sz != HDR_LEN_L2_ONLY);

	/* dmac_47_16 */
	DEVX_SET(dr_action_hw_set, ops + i, opcode, MLX5_DR_ACTION_MDFY_HW_OP_SET);
	DEVX_SET(dr_action_hw_set, ops + i, destination_length, 0);
	DEVX_SET(dr_action_hw_set, ops + i, destination_field_code, MLX5_DR_ACTION_MDFY_HW_FLD_L2_0);
	DEVX_SET(dr_action_hw_set, ops + i, destination_left_shifter, 16);
	hdr_fld_4b = DEVX_GET(l2_hdr, l2_hdr, dmac_47_16);
	DEVX_SET(dr_action_hw_set, ops + i, inline_data, hdr_fld_4b);
	i++;

	/* smac_47_16 */
	DEVX_SET(dr_action_hw_set, ops + i, opcode, MLX5_DR_ACTION_MDFY_HW_OP_SET);
	DEVX_SET(dr_action_hw_set, ops + i, destination_length, 0);
	DEVX_SET(dr_action_hw_set, ops + i, destination_field_code, MLX5_DR_ACTION_MDFY_HW_FLD_L2_1);
	DEVX_SET(dr_action_hw_set, ops + i, destination_left_shifter, 16);
	hdr_fld_4b = (DEVX_GET(l2_hdr, l2_hdr, smac_31_0) >> 16 |
		      DEVX_GET(l2_hdr, l2_hdr, smac_47_32) << 16);
	DEVX_SET(dr_action_hw_set, ops + i, inline_data, hdr_fld_4b);
	i++;

	/* dmac_15_0 */
	DEVX_SET(dr_action_hw_set, ops + i, opcode, MLX5_DR_ACTION_MDFY_HW_OP_SET);
	DEVX_SET(dr_action_hw_set, ops + i, destination_length, 16);
	DEVX_SET(dr_action_hw_set, ops + i, destination_field_code, MLX5_DR_ACTION_MDFY_HW_FLD_L2_0);
	DEVX_SET(dr_action_hw_set, ops + i, destination_left_shifter, 0);
	hdr_fld_2b = DEVX_GET(l2_hdr, l2_hdr, dmac_15_0);
	DEVX_SET(dr_action_hw_set, ops + i, inline_data, hdr_fld_2b);
	i++;

	/* ethertype + (optional) vlan */
	DEVX_SET(dr_action_hw_set, ops + i, opcode, MLX5_DR_ACTION_MDFY_HW_OP_SET);
	DEVX_SET(dr_action_hw_set, ops + i, destination_field_code, MLX5_DR_ACTION_MDFY_HW_FLD_L2_2);
	DEVX_SET(dr_action_hw_set, ops + i, destination_left_shifter, 32);
	if (!vlan) {
		hdr_fld_2b = DEVX_GET(l2_hdr, l2_hdr, ethertype);
		DEVX_SET(dr_action_hw_set, ops + i, inline_data, hdr_fld_2b);
		DEVX_SET(dr_action_hw_set, ops + i, destination_length, 16);
	} else {
		hdr_fld_2b = DEVX_GET(l2_hdr, l2_hdr, ethertype);
		vlan_type = hdr_fld_2b == SVLAN_ETHERTYPE ? DR_STE_SVLAN : DR_STE_CVLAN;
		hdr_fld_2b = DEVX_GET(l2_hdr, l2_hdr, vlan);
		hdr_fld_4b = (vlan_type << 16) | hdr_fld_2b;
		DEVX_SET(dr_action_hw_set, ops + i, inline_data, hdr_fld_4b);
		DEVX_SET(dr_action_hw_set, ops + i, destination_length, 18);
	}
	i++;

	/* smac_15_0 */
	DEVX_SET(dr_action_hw_set, ops + i, opcode, MLX5_DR_ACTION_MDFY_HW_OP_SET);
	DEVX_SET(dr_action_hw_set, ops + i, destination_length, 16);
	DEVX_SET(dr_action_hw_set, ops + i, destination_field_code, MLX5_DR_ACTION_MDFY_HW_FLD_L2_1);
	DEVX_SET(dr_action_hw_set, ops + i, destination_left_shifter, 0);
	hdr_fld_2b = DEVX_GET(l2_hdr, l2_hdr, smac_31_0);
	DEVX_SET(dr_action_hw_set, ops + i, inline_data, hdr_fld_2b);
	i++;

	if (vlan) {
		DEVX_SET(dr_action_hw_set, ops + i, opcode, MLX5_DR_ACTION_MDFY_HW_OP_SET);
		hdr_fld_2b = DEVX_GET(l2_hdr, l2_hdr, vlan_type);
		DEVX_SET(dr_action_hw_set, ops + i, inline_data, hdr_fld_2b);
		DEVX_SET(dr_action_hw_set, ops + i, destination_length, 16);
		DEVX_SET(dr_action_hw_set, ops + i, destination_field_code, MLX5_DR_ACTION_MDFY_HW_FLD_L2_2);
		DEVX_SET(dr_action_hw_set, ops + i, destination_left_shifter, 0);
		i++;
	}

	action->rewrite.data = (void *)ops;
	action->rewrite.num_of_actions = i;
	action->rewrite.chunk->byte_size = i * sizeof(*ops);

	ret = dr_send_postsend_action(dmn, action);
	if (ret) {
		dr_dbg(dmn, "Writing encapsulation action to ICM failed\n");
		return ret;
	}

	return 0;
}

static struct mlx5dv_dr_action *
dr_action_create_generic(enum dr_action_type action_type)
{
	struct mlx5dv_dr_action *action;

	action = calloc(1, sizeof(struct mlx5dv_dr_action));
	if (!action) {
		errno = ENOMEM;
		return NULL;
	}

	action->action_type = action_type;
	atomic_init(&action->refcount, 1);

	return action;
}

struct mlx5dv_dr_action *mlx5dv_dr_action_create_drop(void)
{
	return dr_action_create_generic(DR_ACTION_TYP_DROP);
}

struct mlx5dv_dr_action *
mlx5dv_dr_action_create_dest_ibv_qp(struct ibv_qp *ibqp)
{
	struct mlx5dv_dr_action *action;

	if (ibqp->qp_type != IBV_QPT_RAW_PACKET) {
		errno = EINVAL;
		return NULL;
	}

	action = dr_action_create_generic(DR_ACTION_TYP_QP);
	if (!action)
		return NULL;

	action->qp = ibqp;

	return action;
}

struct mlx5dv_dr_action *
mlx5dv_dr_action_create_dest_table(struct mlx5dv_dr_table *tbl)
{
	struct mlx5dv_dr_action *action;

	atomic_fetch_add(&tbl->refcount, 1);

	if (dr_is_root_table(tbl)) {
		dr_dbg(tbl->dmn, "Root table cannot be used as a destination\n");
		errno = EINVAL;
		goto dec_ref;
	}

	action = dr_action_create_generic(DR_ACTION_TYP_FT);
	if (!action)
		goto dec_ref;

	action->dest_tbl = tbl;

	return action;

dec_ref:
	atomic_fetch_sub(&tbl->refcount, 1);
	return NULL;
}

struct mlx5dv_dr_action *
mlx5dv_dr_action_create_flow_counter(struct mlx5dv_devx_obj *devx_obj,
				     uint32_t offeset)
{
	struct mlx5dv_dr_action *action;

	if (devx_obj->type != MLX5_DEVX_FLOW_COUNTER) {
		errno = EINVAL;
		return NULL;
	}

	action = dr_action_create_generic(DR_ACTION_TYP_CTR);
	if (!action)
		return NULL;

	action->ctr.devx_obj = devx_obj;
	action->ctr.offeset = offeset;

	return action;
}

struct mlx5dv_dr_action *mlx5dv_dr_action_create_tag(uint32_t tag_value)
{
	struct mlx5dv_dr_action *action;

	action = dr_action_create_generic(DR_ACTION_TYP_TAG);
	if (!action)
		return NULL;

	action->flow_tag = tag_value & 0xffffff;

	return action;
}

static int
dr_action_create_reformat_action_root(struct mlx5dv_dr_domain *dmn,
				      size_t data_sz,
				      void *data,
				      struct mlx5dv_dr_action *action)
{
	enum mlx5dv_flow_action_packet_reformat_type  reformat_type;
	struct ibv_flow_action *flow_action;
	enum mlx5dv_flow_table_type type;

	if (dmn->type == MLX5DV_DR_DOMAIN_TYPE_NIC_RX)
		type = MLX5_IB_UAPI_FLOW_TABLE_TYPE_NIC_RX;
	else if (dmn->type == MLX5DV_DR_DOMAIN_TYPE_NIC_TX)
		type = MLX5_IB_UAPI_FLOW_TABLE_TYPE_NIC_TX;
	else
		type = MLX5_IB_UAPI_FLOW_TABLE_TYPE_FDB;

	reformat_type = dr_action_type_to_reformat_enum(action->action_type);
	flow_action = mlx5dv_create_flow_action_packet_reformat(dmn->ctx,
								data_sz,
								data,
								reformat_type,
								type);
	if (!flow_action)
		return errno;

	action->reformat.flow_action = flow_action;
	return 0;
}

static int
dr_action_verify_reformat_params(enum mlx5dv_flow_action_packet_reformat_type reformat_type,
				 struct mlx5dv_dr_domain *dmn,
				 size_t data_sz,
				 void *data)
{
	if ((!data && data_sz) || (data && !data_sz) || reformat_type >
	    MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L3_TUNNEL) {
		dr_dbg(dmn, "Invalid reformat parameter!\n");
		goto out_err;
	}

	if (dmn->type == MLX5DV_DR_DOMAIN_TYPE_FDB)
		return 0;

	if (dmn->type == MLX5DV_DR_DOMAIN_TYPE_NIC_RX) {
		if (reformat_type != MLX5_IB_UAPI_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TUNNEL_TO_L2 &&
		    reformat_type != MLX5_IB_UAPI_FLOW_ACTION_PACKET_REFORMAT_TYPE_L3_TUNNEL_TO_L2) {
			dr_dbg(dmn, "Action reformat type not support on RX domain\n");
			goto out_err;
		}
	} else if (dmn->type == MLX5DV_DR_DOMAIN_TYPE_NIC_TX) {
		if (reformat_type != MLX5_IB_UAPI_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L2_TUNNEL &&
		    reformat_type != MLX5_IB_UAPI_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L3_TUNNEL) {
			dr_dbg(dmn, "Action reformat type not support on TX domain\n");
			goto out_err;
		}
	}

	return 0;

out_err:
	errno = EINVAL;
	return errno;
}

#define ACTION_CACHE_LINE_SIZE 64

static int
dr_action_create_reformat_action(struct mlx5dv_dr_domain *dmn,
				 size_t data_sz, void *data,
				 struct mlx5dv_dr_action *action)
{
	struct mlx5dv_devx_obj *obj;

	switch (action->action_type) {
	case DR_ACTION_TYP_L2_TO_TNL_L2:
	case DR_ACTION_TYP_L2_TO_TNL_L3:
	{
		enum reformat_type rt;

		if (action->action_type == DR_ACTION_TYP_L2_TO_TNL_L2)
			rt = MLX5_REFORMAT_TYPE_L2_TO_L2_TUNNEL;
		else
			rt = MLX5_REFORMAT_TYPE_L2_TO_L3_TUNNEL;

		obj = dr_devx_create_reformat_ctx(dmn->ctx, rt, data_sz, data);
		if (!obj)
			return errno;

		action->reformat.dvo = obj;
		action->reformat.reformat_size = data_sz;
		return 0;
	}
	case DR_ACTION_TYP_TNL_L2_TO_L2:
	{
		return 0;
	}
	case DR_ACTION_TYP_TNL_L3_TO_L2:
	{
		int ret;

		/* Only Ethernet frame is supported, with VLAN (18) or without (14) */
		if (data_sz != HDR_LEN_L2_ONLY && data_sz != HDR_LEN_L2_VLAN) {
			errno = EINVAL;
			return errno;
		}

		action->rewrite.chunk = dr_icm_alloc_chunk(dmn->action_icm_pool,
							   DR_CHUNK_SIZE_8);
		if (!action->rewrite.chunk)
			return errno;

		action->rewrite.index = (action->rewrite.chunk->icm_addr -
					 dmn->info.caps.hdr_modify_icm_addr) /
					 ACTION_CACHE_LINE_SIZE;

		ret = dr_actions_l2_rewrite(dmn, action, data, data_sz);
		if (ret) {
			dr_icm_free_chunk(action->rewrite.chunk);
			return ret;
		}
		return 0;
	}
	default:
		dr_dbg(dmn, "Reformat type is not supported %d\n", action->action_type);
		errno = ENOTSUP;
		return errno;
	}
}

struct mlx5dv_dr_action *
mlx5dv_dr_action_create_packet_reformat(struct mlx5dv_dr_domain *dmn,
					uint32_t flags,
					enum mlx5dv_flow_action_packet_reformat_type reformat_type,
					size_t data_sz,
					void *data)
{
	struct mlx5dv_dr_action *action;
	enum dr_action_type action_type;
	int ret;

	atomic_fetch_add(&dmn->refcount, 1);

	if (!check_comp_mask(flags, MLX5DV_DR_ACTION_FLAGS_ROOT_LEVEL)) {
		errno = EINVAL;
		goto dec_ref;
	}

	if (!dmn->info.supp_sw_steering &&
	    !(flags & MLX5DV_DR_ACTION_FLAGS_ROOT_LEVEL)) {
		dr_dbg(dmn, "Only root actions are supported on current domain\n");
		errno = EOPNOTSUPP;
		goto dec_ref;
	}

	/* General checks */
	ret = dr_action_verify_reformat_params(reformat_type, dmn, data_sz, data);
	if (ret)
		goto dec_ref;

	action_type = dr_action_reformat_to_action_type(reformat_type);
	action = dr_action_create_generic(action_type);
	if (!action)
		goto dec_ref;

	action->reformat.dmn = dmn;

	/* Create the action according to the table type */
	if (flags & MLX5DV_DR_ACTION_FLAGS_ROOT_LEVEL) {
		action->reformat.is_root_level = true;
		ret = dr_action_create_reformat_action_root(dmn,
							    data_sz,
							    data,
							    action);
	} else {
		action->reformat.is_root_level = false;
		ret = dr_action_create_reformat_action(dmn,
						       data_sz,
						       data,
						       action);
	}

	if (ret) {
		dr_dbg(dmn, "Failed creating reformat action %d\n", ret);
		goto free_action;
	}

	return action;

free_action:
	free(action);
dec_ref:
	atomic_fetch_sub(&dmn->refcount, 1);
	return NULL;
}

static const struct dr_action_modify_field_conv *
dr_action_modify_get_hw_info(uint16_t sw_field)
{
	const struct dr_action_modify_field_conv *hw_action_info;

	if (sw_field >= ARRAY_SIZE(dr_action_conv_arr))
		goto not_found;

	hw_action_info = &dr_action_conv_arr[sw_field];
	if (!hw_action_info->end && !hw_action_info->start)
		goto not_found;

	return hw_action_info;

not_found:
	errno = EINVAL;
	return NULL;
}

static int
dr_action_modify_sw_to_hw(struct mlx5dv_dr_domain *dmn,
			  __be64 *sw_action,
			  __be64 *hw_action,
			  const struct dr_action_modify_field_conv **ret_hw_info)
{
	const struct dr_action_modify_field_conv *hw_action_info;
	uint8_t offset, length, max_length, action;
	uint16_t sw_field;
	uint8_t hw_opcode;
	uint32_t data;

	/* Get SW modify action data */
	action = DEVX_GET(set_action_in, sw_action, action_type);
	length = DEVX_GET(set_action_in, sw_action, length);
	offset = DEVX_GET(set_action_in, sw_action, offset);
	sw_field = DEVX_GET(set_action_in, sw_action, field);
	data = DEVX_GET(set_action_in, sw_action, data);

	/* Convert SW data to HW modify action format */
	hw_action_info = dr_action_modify_get_hw_info(sw_field);
	if (!hw_action_info) {
		dr_dbg(dmn, "Modify action invalid field given\n");
		errno = EINVAL;
		return errno;
	}

	max_length = hw_action_info->end - hw_action_info->start + 1;

	switch (action) {
	case MLX5_ACTION_TYPE_SET:
		hw_opcode = MLX5_DR_ACTION_MDFY_HW_OP_SET;
		/* PRM defines that length zero specific length of 32bits */
		if (!length)
			length = 32;

		if (length + offset > max_length) {
			dr_dbg(dmn, "Modify action length + offset exceeds limit\n");
			errno = EINVAL;
			return errno;
		}
		break;

	case MLX5_ACTION_TYPE_ADD:
		hw_opcode = MLX5_DR_ACTION_MDFY_HW_OP_ADD;
		offset = 0;
		length = max_length;
		break;

	default:
		dr_dbg(dmn, "Unsupported action_type for modify action\n");
		errno = EOPNOTSUPP;
		return errno;
	}

	DEVX_SET(dr_action_hw_set, hw_action, opcode, hw_opcode);

	DEVX_SET(dr_action_hw_set, hw_action, destination_field_code,
		 hw_action_info->hw_field);

	DEVX_SET(dr_action_hw_set, hw_action, destination_left_shifter,
		 hw_action_info->start + offset);

	DEVX_SET(dr_action_hw_set, hw_action, destination_length,
		 length == 32 ? 0 : length);

	DEVX_SET(dr_action_hw_set, hw_action, inline_data, data);

	*ret_hw_info = hw_action_info;

	return 0;
}

static int
dr_action_modify_check_field_limitation(struct mlx5dv_dr_domain *dmn,
					const __be64 *sw_action)
{
	uint16_t sw_field;
	uint8_t action;

	sw_field = DEVX_GET(set_action_in, sw_action, field);
	action = DEVX_GET(set_action_in, sw_action, action_type);

	/* Check if SW field is supported in current domain (RX/TX) */
	if (action == MLX5_ACTION_TYPE_SET) {
		if (sw_field == MLX5_ACTION_IN_FIELD_OUT_METADATA_REGA) {
			if (dmn->type != MLX5DV_DR_DOMAIN_TYPE_NIC_TX) {
				dr_dbg(dmn, "Unsupported field %d for RX/FDB set action\n",
				       sw_field);
				errno = EINVAL;
				return errno;
			}
		}

		if (sw_field == MLX5_ACTION_IN_FIELD_OUT_METADATA_REGB) {
			if (dmn->type != MLX5DV_DR_DOMAIN_TYPE_NIC_RX) {
				dr_dbg(dmn, "Unsupported field %d for TX/FDB set action\n",
				       sw_field);
				errno = EINVAL;
				return errno;
			}
		}
	} else if (action == MLX5_ACTION_TYPE_ADD) {
		if (sw_field != MLX5_ACTION_IN_FIELD_OUT_IP_TTL &&
		    sw_field != MLX5_ACTION_IN_FIELD_OUT_IPV6_HOPLIMIT &&
		    sw_field != MLX5_ACTION_IN_FIELD_OUT_TCP_SEQ_NUM &&
		    sw_field != MLX5_ACTION_IN_FIELD_OUT_TCP_ACK_NUM) {
			dr_dbg(dmn, "Unsupported field %d for add action\n", sw_field);
			errno = EINVAL;
			return errno;
		}
	} else {
		dr_dbg(dmn, "Unsupported action %d modify action\n", action);
		errno = EOPNOTSUPP;
		return errno;
	}

	return 0;
}

static int dr_actions_convert_modify_header(struct mlx5dv_dr_domain *dmn,
					    uint32_t max_hw_actions,
					    uint32_t num_sw_actions,
					    __be64 sw_actions[],
					    __be64 hw_actions[],
					    uint32_t *num_hw_actions)
{
	const struct dr_action_modify_field_conv *hw_action_info;
	uint16_t hw_field = MLX5_DR_ACTION_MDFY_HW_FLD_RESERVED;
	uint32_t l3_type = MLX5_DR_ACTION_MDFY_HW_HDR_L3_NONE;
	uint32_t l4_type = MLX5_DR_ACTION_MDFY_HW_HDR_L4_NONE;
	int ret, i, hw_idx = 0;
	__be64 *sw_action;
	__be64 hw_action;

	for (i = 0; i < num_sw_actions; i++) {
		sw_action = &sw_actions[i];

		ret = dr_action_modify_check_field_limitation(dmn, sw_action);
		if (ret)
			return ret;

		/* Convert SW action to HW action */
		ret = dr_action_modify_sw_to_hw(dmn,
						sw_action,
						&hw_action,
						&hw_action_info);
		if (ret)
			return ret;

		/* Due to a HW limitation we cannot modify 2 different L3 types */
		if (l3_type && hw_action_info->l3_type &&
		    (hw_action_info->l3_type != l3_type)) {
			dr_dbg(dmn, "Action list can't support two different L3 types\n");
			errno = ENOTSUP;
			return errno;
		}
		if (hw_action_info->l3_type)
			l3_type = hw_action_info->l3_type;

		/* Due to a HW limitation we cannot modify two different L4 types */
		if (l4_type && hw_action_info->l4_type &&
		    (hw_action_info->l4_type != l4_type)) {
			dr_dbg(dmn, "Action list can't support two different L4 types\n");
			errno = EINVAL;
			return errno;
		}
		if (hw_action_info->l4_type)
			l4_type = hw_action_info->l4_type;

		/* HW reads and executes two actions at once this means we
		 * need to create a gap if two actions access the same field
		 */
		if ((hw_idx % 2) && (hw_field == hw_action_info->hw_field)) {
			/* Check if after gap insertion the total number of HW
			 * modify actions doesn't exceeds the limit
			 */
			hw_idx++;
			if ((num_sw_actions + hw_idx - i) >= max_hw_actions) {
				dr_dbg(dmn, "Modify header action number exceeds HW limit\n");
				errno = EINVAL;
				return errno;
			}
		}
		hw_field = hw_action_info->hw_field;

		hw_actions[hw_idx] = hw_action;
		hw_idx++;
	}

	*num_hw_actions = hw_idx;

	return 0;
}

static int
dr_action_create_modify_action_root(struct mlx5dv_dr_domain *dmn,
				    size_t actions_sz,
				    __be64 actions[],
				    struct mlx5dv_dr_action *action)
{
	struct ibv_flow_action *flow_action;
	enum mlx5dv_flow_table_type type;

	if (dmn->type == MLX5DV_DR_DOMAIN_TYPE_NIC_RX)
		type = MLX5_IB_UAPI_FLOW_TABLE_TYPE_NIC_RX;
	else if (dmn->type == MLX5DV_DR_DOMAIN_TYPE_NIC_TX)
		type = MLX5_IB_UAPI_FLOW_TABLE_TYPE_NIC_TX;
	else
		type = MLX5_IB_UAPI_FLOW_TABLE_TYPE_FDB;

	flow_action = mlx5dv_create_flow_action_modify_header(dmn->ctx,
							      actions_sz,
							      (__force uint64_t *)actions,
							      type);
	if (!flow_action)
		return errno;

	action->rewrite.flow_action = flow_action;
	return 0;
}

static int dr_action_create_modify_action(struct mlx5dv_dr_domain *dmn,
					  size_t actions_sz,
					  __be64 actions[],
					  struct mlx5dv_dr_action *action)
{
	struct dr_icm_chunk *chunk;
	uint32_t max_hw_actions;
	uint32_t num_hw_actions;
	uint32_t num_sw_actions;
	__be64 *hw_actions;
	int ret;

	num_sw_actions = actions_sz / DR_MODIFY_ACTION_SIZE;
	max_hw_actions = dr_icm_pool_chunk_size_to_entries(DR_CHUNK_SIZE_8);

	if (num_sw_actions > max_hw_actions) {
		dr_dbg(dmn, "Max number of actions %d exceeds limit %d\n",
		       num_sw_actions, max_hw_actions);
		errno = EINVAL;
		return errno;
	}

	chunk = dr_icm_alloc_chunk(dmn->action_icm_pool, DR_CHUNK_SIZE_8);
	if (!chunk)
		return errno;

	hw_actions = calloc(1, max_hw_actions * DR_MODIFY_ACTION_SIZE);
	if (!hw_actions) {
		errno = ENOMEM;
		goto free_chunk;
	}

	ret = dr_actions_convert_modify_header(dmn,
					       max_hw_actions,
					       num_sw_actions,
					       actions,
					       hw_actions,
					       &num_hw_actions);
	if (ret)
		goto free_hw_actions;

	action->rewrite.chunk = chunk;
	action->rewrite.data = (uint8_t *)hw_actions;
	action->rewrite.num_of_actions = num_hw_actions;
	action->rewrite.index = (chunk->icm_addr -
				 dmn->info.caps.hdr_modify_icm_addr) /
				 ACTION_CACHE_LINE_SIZE;

	ret = dr_send_postsend_action(dmn, action);
	if (ret)
		goto free_hw_actions;

	return 0;

free_hw_actions:
	free(hw_actions);
free_chunk:
	dr_icm_free_chunk(chunk);
	return errno;
}

struct mlx5dv_dr_action *
mlx5dv_dr_action_create_modify_header(struct mlx5dv_dr_domain *dmn,
				      uint32_t flags,
				      size_t actions_sz,
				      __be64 actions[])
{
	struct mlx5dv_dr_action *action;
	int ret = 0;

	atomic_fetch_add(&dmn->refcount, 1);

	if (!check_comp_mask(flags, MLX5DV_DR_ACTION_FLAGS_ROOT_LEVEL)) {
		errno = EINVAL;
		goto dec_ref;
	}

	if (actions_sz % DR_MODIFY_ACTION_SIZE) {
		dr_dbg(dmn, "Invalid modify actions size provided\n");
		errno = EINVAL;
		goto dec_ref;
	}

	if (!dmn->info.supp_sw_steering &&
	    !(flags & MLX5DV_DR_ACTION_FLAGS_ROOT_LEVEL)) {
		dr_dbg(dmn, "Only root actions are supported on current domain\n");
		errno = EOPNOTSUPP;
		goto dec_ref;
	}

	action = dr_action_create_generic(DR_ACTION_TYP_MODIFY_HDR);
	if (!action)
		goto dec_ref;

	action->rewrite.dmn = dmn;

	/* Create the action according to the table type */
	if (flags & MLX5DV_DR_ACTION_FLAGS_ROOT_LEVEL) {
		action->rewrite.is_root_level = true;
		ret = dr_action_create_modify_action_root(dmn,
							  actions_sz,
							  actions,
							  action);
	} else {
		action->rewrite.is_root_level = false;
		ret = dr_action_create_modify_action(dmn,
						     actions_sz,
						     actions,
						     action);
	}

	if (ret) {
		dr_dbg(dmn, "Failed creating modify header action %d\n", ret);
		goto free_action;
	}

	return action;

free_action:
	free(action);
dec_ref:
	atomic_fetch_sub(&dmn->refcount, 1);
	return NULL;
}

struct mlx5dv_dr_action
*mlx5dv_dr_action_create_dest_vport(struct mlx5dv_dr_domain *dmn, uint32_t vport)
{
	struct mlx5dv_dr_action *action;
	struct dr_devx_vport_cap *vport_cap;

	if (!dmn->info.supp_sw_steering ||
	    dmn->type != MLX5DV_DR_DOMAIN_TYPE_FDB) {
		dr_dbg(dmn, "Domain doesn't support vport actions\n");
		errno = EOPNOTSUPP;
		return NULL;
	}

	vport_cap = dr_get_vport_cap(&dmn->info.caps, vport);
	if (!vport_cap) {
		dr_dbg(dmn, "Failed to get vport %d caps\n", vport);
		return NULL;
	}

	action = dr_action_create_generic(DR_ACTION_TYP_VPORT);
	if (!action)
		return NULL;

	action->vport.dmn = dmn;
	action->vport.num = vport;
	action->vport.caps = vport_cap;

	return action;
}

int mlx5dv_dr_action_destroy(struct mlx5dv_dr_action *action)
{
	if (atomic_load(&action->refcount) > 1)
		return EBUSY;

	switch (action->action_type) {
	case DR_ACTION_TYP_FT:
		atomic_fetch_sub(&action->dest_tbl->refcount, 1);
		break;
	case DR_ACTION_TYP_TNL_L2_TO_L2:
		if (action->reformat.is_root_level)
			mlx5_destroy_flow_action(action->reformat.flow_action);
		atomic_fetch_sub(&action->reformat.dmn->refcount, 1);
		break;
	case DR_ACTION_TYP_TNL_L3_TO_L2:
		if (action->reformat.is_root_level)
			mlx5_destroy_flow_action(action->reformat.flow_action);
		else
			dr_icm_free_chunk(action->rewrite.chunk);
		atomic_fetch_sub(&action->reformat.dmn->refcount, 1);
		break;
	case DR_ACTION_TYP_L2_TO_TNL_L2:
	case DR_ACTION_TYP_L2_TO_TNL_L3:
		if (action->reformat.is_root_level)
			mlx5_destroy_flow_action(action->reformat.flow_action);
		else
			mlx5dv_devx_obj_destroy(action->reformat.dvo);
		atomic_fetch_sub(&action->reformat.dmn->refcount, 1);
		break;
	case DR_ACTION_TYP_MODIFY_HDR:
		if (action->rewrite.is_root_level) {
			mlx5_destroy_flow_action(action->rewrite.flow_action);
		} else {
			dr_icm_free_chunk(action->rewrite.chunk);
			free(action->rewrite.data);
		}
		atomic_fetch_sub(&action->rewrite.dmn->refcount, 1);
		break;
	default:
		break;
	}

	free(action);
	return 0;
}
