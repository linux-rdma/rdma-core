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

#ifndef	_DR_STE_
#define	_DR_STE_

#include <ccan/array_size.h>
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
#define HDR_LEN_L2_MACS   0xC
#define HDR_LEN_L2_VLAN   0x4
#define HDR_LEN_L2_ETHER  0x2
#define HDR_LEN_L2        (HDR_LEN_L2_MACS + HDR_LEN_L2_ETHER)
#define HDR_LEN_L2_W_VLAN (HDR_LEN_L2 + HDR_LEN_L2_VLAN)

enum {
	HDR_MPLS_OFFSET_LABEL	= 12,
	HDR_MPLS_OFFSET_EXP	= 9,
	HDR_MPLS_OFFSET_S_BOS	= 8,
	HDR_MPLS_OFFSET_TTL	= 0,
};

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

/* Set to STE spec->s_fname to tag->t_fname set spec->s_fname as used */
#define DR_STE_SET_TAG(lookup_type, tag, t_fname, spec, s_fname) \
	DR_STE_SET_VAL(lookup_type, tag, t_fname, spec, s_fname, (spec)->s_fname)

/* Set to STE -1 to tag->t_fname and set spec->s_fname as used */
#define DR_STE_SET_ONES(lookup_type, tag, t_fname, spec, s_fname) \
	DR_STE_SET_VAL(lookup_type, tag, t_fname, spec, s_fname, -1)

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

#define DR_STE_SET_MPLS(lookup_type, mask, in_out, tag) do { \
	DR_STE_SET_TAG(lookup_type, tag, mpls0_label, mask, \
		       in_out##_first_mpls_label);\
	DR_STE_SET_TAG(lookup_type, tag, mpls0_s_bos, mask, \
		       in_out##_first_mpls_s_bos); \
	DR_STE_SET_TAG(lookup_type, tag, mpls0_exp, mask, \
		       in_out##_first_mpls_exp); \
	DR_STE_SET_TAG(lookup_type, tag, mpls0_ttl, mask, \
		       in_out##_first_mpls_ttl); \
} while (0)

#define DR_STE_SET_FLEX_PARSER_FIELD(tag, fname, caps, spec) do { \
	if ((spec)->fname) { \
		uint8_t parser_id = caps->flex_parser_id_##fname; \
		uint8_t *parser_ptr = dr_ste_calc_flex_parser_offset(tag, parser_id); \
		*(__be32 *)parser_ptr = htobe32((spec)->fname);\
		(spec)->fname = 0; \
	} \
} while (0)

enum dr_ste_action_modify_flags {
	DR_STE_ACTION_MODIFY_FLAG_REQ_FLEX      = 1 << 0,
};

enum dr_ste_action_modify_type_l3 {
	DR_STE_ACTION_MDFY_TYPE_L3_NONE	= 0x0,
	DR_STE_ACTION_MDFY_TYPE_L3_IPV4	= 0x1,
	DR_STE_ACTION_MDFY_TYPE_L3_IPV6	= 0x2,
};

enum dr_ste_action_modify_type_l4 {
	DR_STE_ACTION_MDFY_TYPE_L4_NONE	= 0x0,
	DR_STE_ACTION_MDFY_TYPE_L4_TCP	= 0x1,
	DR_STE_ACTION_MDFY_TYPE_L4_UDP	= 0x2,
};

uint16_t dr_ste_conv_bit_to_byte_mask(uint8_t *bit_mask);

static inline uint8_t *
dr_ste_calc_flex_parser_offset(uint8_t *tag, uint8_t parser_id)
{
	/* Calculate tag byte offset based on flex parser id */
	return tag + 4 * (3 - (parser_id % 4));
}

typedef void (*dr_ste_builder_void_init)(struct dr_ste_build *sb,
					 struct dr_match_param *mask);

struct dr_ste_ctx {
	/* Builders */
	dr_ste_builder_void_init build_eth_l2_src_dst_init;
	dr_ste_builder_void_init build_eth_l3_ipv6_src_init;
	dr_ste_builder_void_init build_eth_l3_ipv6_dst_init;
	dr_ste_builder_void_init build_eth_l3_ipv4_5_tuple_init;
	dr_ste_builder_void_init build_eth_l2_src_init;
	dr_ste_builder_void_init build_eth_l2_dst_init;
	dr_ste_builder_void_init build_eth_l2_tnl_init;
	dr_ste_builder_void_init build_eth_l3_ipv4_misc_init;
	dr_ste_builder_void_init build_eth_ipv6_l3_l4_init;
	dr_ste_builder_void_init build_mpls_init;
	dr_ste_builder_void_init build_tnl_gre_init;
	dr_ste_builder_void_init build_tnl_mpls_over_gre_init;
	dr_ste_builder_void_init build_tnl_mpls_over_udp_init;
	dr_ste_builder_void_init build_icmp_init;
	dr_ste_builder_void_init build_general_purpose_init;
	dr_ste_builder_void_init build_eth_l4_misc_init;
	dr_ste_builder_void_init build_tnl_vxlan_gpe_init;
	dr_ste_builder_void_init build_tnl_geneve_init;
	dr_ste_builder_void_init build_tnl_geneve_tlv_opt_init;
	dr_ste_builder_void_init build_tnl_gtpu_init;
	dr_ste_builder_void_init build_tnl_gtpu_flex_parser_0;
	dr_ste_builder_void_init build_tnl_gtpu_flex_parser_1;
	dr_ste_builder_void_init build_register_0_init;
	dr_ste_builder_void_init build_register_1_init;
	dr_ste_builder_void_init build_src_gvmi_qpn_init;
	dr_ste_builder_void_init build_flex_parser_0_init;
	dr_ste_builder_void_init build_flex_parser_1_init;
	dr_ste_builder_void_init build_tunnel_header_0_1;
	dr_ste_builder_void_init build_def0_init;
	dr_ste_builder_void_init build_def2_init;
	dr_ste_builder_void_init build_def6_init;
	dr_ste_builder_void_init build_def16_init;
	dr_ste_builder_void_init build_def22_init;
	dr_ste_builder_void_init build_def24_init;
	dr_ste_builder_void_init build_def25_init;
	dr_ste_builder_void_init build_def26_init;
	dr_ste_builder_void_init build_def28_init;
	dr_ste_builder_void_init build_def33_init;
	int (*aso_other_domain_link)(struct mlx5dv_devx_obj *devx_obj,
				     struct mlx5dv_dr_domain *peer_dmn,
				     struct mlx5dv_dr_domain *dmn,
				     uint32_t flags,
				     uint8_t return_reg_c);
	int (*aso_other_domain_unlink)(struct mlx5dv_devx_obj *devx_obj);

	/* Getters and Setters */
	void (*ste_init)(uint8_t *hw_ste_p, uint16_t lu_type,
			 bool is_rx, uint16_t gvmi);
	void (*set_next_lu_type)(uint8_t *hw_ste_p, uint16_t lu_type);
	uint16_t (*get_next_lu_type)(uint8_t *hw_ste_p);
	void (*set_miss_addr)(uint8_t *hw_ste_p, uint64_t miss_addr);
	uint64_t (*get_miss_addr)(uint8_t *hw_ste_p);
	void (*set_hit_addr)(uint8_t *hw_ste_p, uint64_t icm_addr, uint32_t ht_size);
	void (*set_byte_mask)(uint8_t *hw_ste_p, uint16_t byte_mask);
	uint16_t (*get_byte_mask)(uint8_t *hw_ste_p);
	void (*set_ctrl_always_hit_htbl)(uint8_t *hw_ste, uint16_t byte_mask,
					 uint16_t lu_type, uint64_t icm_addr,
					 uint32_t num_of_entries, uint16_t gvmi);
	void (*set_ctrl_always_miss)(uint8_t *hw_ste,
				     uint64_t miss_addr,
				     uint16_t gvmi);
	void (*set_hit_gvmi)(uint8_t *hw_ste, uint16_t gvmi);

	/* Actions */
	uint32_t actions_caps;
	void (*set_actions_rx)(uint8_t *action_type_set,
			       uint8_t *hw_ste_arr,
			       struct dr_ste_actions_attr *attr,
			       uint32_t *added_stes);
	void (*set_actions_tx)(uint8_t *action_type_set,
			       uint8_t *hw_ste_arr,
			       struct dr_ste_actions_attr *attr,
			       uint32_t *added_stes);
	void (*set_action_set)(uint8_t *hw_action,
			       uint8_t hw_field,
			       uint8_t shifter,
			       uint8_t length,
			       uint32_t data);
	void (*set_action_add)(uint8_t *hw_action,
			       uint8_t hw_field,
			       uint8_t shifter,
			       uint8_t length,
			       uint32_t data);
	void (*set_action_copy)(uint8_t *hw_action,
				uint8_t dst_hw_field,
				uint8_t dst_shifter,
				uint8_t dst_len,
				uint8_t src_hw_field,
				uint8_t src_shifter);
	const struct dr_ste_action_modify_field *
		(*get_action_hw_field)(uint16_t sw_field,
				       struct dr_devx_caps *caps);
	int (*set_action_decap_l3_list)(void *data, uint32_t data_sz,
					uint8_t *hw_action, uint32_t hw_action_sz,
					uint16_t *used_hw_action_num);
	void (*set_aso_ct_cross_dmn)(uint8_t *hw_ste, uint32_t object_id,
				     uint32_t offset, uint8_t dest_reg_id,
				     bool direction);

	/* Send */
	void (*prepare_for_postsend)(uint8_t *hw_ste_p, uint32_t ste_size);
};

struct dr_ste_ctx *dr_ste_get_ctx_v0(void);
struct dr_ste_ctx *dr_ste_get_ctx_v1(void);

#endif
