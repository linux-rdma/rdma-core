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
#include "mlx5dv_dr.h"

#define DR_MASK_IPV4_ETHERTYPE        0x0800
#define DR_MASK_IPV6_ETHERTYPE        0x86DD
#define DR_MASK_IP_VERSION_IPV4       0x4
#define DR_MASK_IP_VERSION_IPV6       0x6

static bool dr_mask_is_smac_set(struct dr_match_spec *spec)
{
	return (spec->smac_47_16 || spec->smac_15_0);
}

static bool dr_mask_is_dmac_set(struct dr_match_spec *spec)
{
	return (spec->dmac_47_16 || spec->dmac_15_0);
}

static bool dr_mask_is_src_addr_set(struct dr_match_spec *spec)
{
	return (spec->src_ip_127_96 || spec->src_ip_95_64 ||
		spec->src_ip_63_32 || spec->src_ip_31_0);
}

static bool dr_mask_is_dst_addr_set(struct dr_match_spec *spec)
{
	return (spec->dst_ip_127_96 || spec->dst_ip_95_64 ||
		spec->dst_ip_63_32 || spec->dst_ip_31_0);
}

static bool dr_mask_is_l3_base_set(struct dr_match_spec *spec)
{
	return (spec->ip_protocol || spec->frag || spec->tcp_flags ||
		spec->ip_ecn || spec->ip_dscp);
}

static bool dr_mask_is_tcp_udp_base_set(struct dr_match_spec *spec)
{
	return (spec->tcp_sport || spec->tcp_dport ||
		spec->udp_sport || spec->udp_dport);
}

static bool dr_mask_is_ipv4_set(struct dr_match_spec *spec)
{
	return (spec->dst_ip_31_0 || spec->src_ip_31_0);
}

static bool dr_mask_is_ipv4_5_tuple_set(struct dr_match_spec *spec)
{
	return (dr_mask_is_l3_base_set(spec) ||
		dr_mask_is_tcp_udp_base_set(spec) ||
		dr_mask_is_ipv4_set(spec));
}

static bool dr_mask_is_eth_l2_tnl_set(struct dr_match_misc *misc)
{
	return misc->vxlan_vni;
}

static bool dr_mask_is_ttl_set(struct dr_match_spec *spec)
{
	return spec->ip_ttl_hoplimit;
}

static bool dr_mask_is_ipv4_ihl_set(struct dr_match_spec *spec)
{
	return spec->ipv4_ihl;
}

#define DR_MASK_IS_L2_DST(_spec, _misc, _inner_outer) (_spec.first_vid || \
	(_spec).first_cfi || (_spec).first_prio || (_spec).cvlan_tag || \
	(_spec).svlan_tag || (_spec).dmac_47_16 || (_spec).dmac_15_0 || \
	(_spec).ethertype || (_spec).ip_version || \
	(_misc)._inner_outer##_second_vid || \
	(_misc)._inner_outer##_second_cfi || \
	(_misc)._inner_outer##_second_prio || \
	(_misc)._inner_outer##_second_cvlan_tag || \
	(_misc)._inner_outer##_second_svlan_tag)

#define DR_MASK_IS_ETH_L4_SET(_spec, _misc, _inner_outer) ( \
	dr_mask_is_l3_base_set(&(_spec)) || \
	dr_mask_is_tcp_udp_base_set(&(_spec)) || \
	dr_mask_is_ttl_set(&(_spec)) || \
	(_misc)._inner_outer##_ipv6_flow_label)

#define DR_MASK_IS_ETH_L4_MISC_SET(_misc3, _inner_outer) ( \
	(_misc3)._inner_outer##_tcp_seq_num || \
	(_misc3)._inner_outer##_tcp_ack_num)

#define DR_MASK_IS_FIRST_MPLS_SET(_misc2, _inner_outer) ( \
	(_misc2)._inner_outer##_first_mpls_label || \
	(_misc2)._inner_outer##_first_mpls_exp || \
	(_misc2)._inner_outer##_first_mpls_s_bos || \
	(_misc2)._inner_outer##_first_mpls_ttl)

static bool dr_mask_is_tnl_gre_set(struct dr_match_misc *misc)
{
	return (misc->gre_key_h || misc->gre_key_l ||
		misc->gre_protocol || misc->gre_c_present ||
		misc->gre_k_present || misc->gre_s_present);
}

#define DR_MASK_IS_OUTER_MPLS_OVER_GRE_SET(_misc) (\
	(_misc)->outer_first_mpls_over_gre_label || \
	(_misc)->outer_first_mpls_over_gre_exp || \
	(_misc)->outer_first_mpls_over_gre_s_bos || \
	(_misc)->outer_first_mpls_over_gre_ttl)

#define DR_MASK_IS_OUTER_MPLS_OVER_UDP_SET(_misc) (\
	(_misc)->outer_first_mpls_over_udp_label || \
	(_misc)->outer_first_mpls_over_udp_exp || \
	(_misc)->outer_first_mpls_over_udp_s_bos || \
	(_misc)->outer_first_mpls_over_udp_ttl)

static bool
dr_mask_is_vxlan_gpe_set(struct dr_match_misc3 *misc3)
{
	return misc3->outer_vxlan_gpe_vni ||
	       misc3->outer_vxlan_gpe_next_protocol ||
	       misc3->outer_vxlan_gpe_flags;
}

static bool
dr_matcher_supp_vxlan_gpe(struct dr_devx_caps *caps)
{
	return (caps->sw_format_ver == MLX5_HW_CONNECTX_6DX) ||
	       (caps->flex_protocols & MLX5_FLEX_PARSER_VXLAN_GPE_ENABLED);
}

static bool
dr_mask_is_tnl_vxlan_gpe(struct dr_match_param *mask,
			 struct mlx5dv_dr_domain *dmn)
{
	return dr_mask_is_vxlan_gpe_set(&mask->misc3) &&
	       dr_matcher_supp_vxlan_gpe(&dmn->info.caps);
}

static bool dr_mask_is_tnl_geneve_set(struct dr_match_misc *misc)
{
	return misc->geneve_vni ||
	       misc->geneve_oam ||
	       misc->geneve_protocol_type ||
	       misc->geneve_opt_len;
}

static int dr_matcher_supp_geneve_tlv_option(struct dr_devx_caps *caps)
{
	return caps->flex_protocols & MLX5_FLEX_PARSER_GENEVE_OPT_0_ENABLED;
}

static bool dr_mask_is_tnl_geneve_tlv_opt(struct dr_match_param *mask,
					  struct mlx5dv_dr_domain *dmn)
{
	return mask->misc3.geneve_tlv_option_0_data &&
	       dr_matcher_supp_geneve_tlv_option(&dmn->info.caps);
}

static bool
dr_matcher_supp_tnl_geneve(struct dr_devx_caps *caps)
{
	return (caps->sw_format_ver == MLX5_HW_CONNECTX_6DX) ||
	       (caps->flex_protocols & MLX5_FLEX_PARSER_GENEVE_ENABLED);
}

static bool
dr_mask_is_tnl_geneve(struct dr_match_param *mask,
		      struct mlx5dv_dr_domain *dmn)
{
	return dr_mask_is_tnl_geneve_set(&mask->misc) &&
	       dr_matcher_supp_tnl_geneve(&dmn->info.caps);
}

static bool dr_mask_is_tnl_gtpu_set(struct dr_match_misc3 *misc3)
{
	return misc3->gtpu_msg_flags || misc3->gtpu_msg_type || misc3->gtpu_teid;
}

static bool dr_matcher_supp_tnl_gtpu(struct dr_devx_caps *caps)
{
	return caps->flex_protocols & MLX5_FLEX_PARSER_GTPU_ENABLED;
}

static bool dr_mask_is_tnl_gtpu(struct dr_match_param *mask,
				struct mlx5dv_dr_domain *dmn)
{
	return dr_mask_is_tnl_gtpu_set(&mask->misc3) &&
	       dr_matcher_supp_tnl_gtpu(&dmn->info.caps);
}

static int dr_matcher_supp_tnl_gtpu_dw_0(struct dr_devx_caps *caps)
{
	return caps->flex_protocols & MLX5_FLEX_PARSER_GTPU_DW_0_ENABLED;
}

static bool dr_mask_is_tnl_gtpu_dw_0(struct dr_match_param *mask,
				     struct mlx5dv_dr_domain *dmn)
{
	return mask->misc3.gtpu_dw_0 &&
	       dr_matcher_supp_tnl_gtpu_dw_0(&dmn->info.caps);
}

static int dr_matcher_supp_tnl_gtpu_teid(struct dr_devx_caps *caps)
{
	return caps->flex_protocols & MLX5_FLEX_PARSER_GTPU_TEID_ENABLED;
}

static bool dr_mask_is_tnl_gtpu_teid(struct dr_match_param *mask,
				     struct mlx5dv_dr_domain *dmn)
{
	return mask->misc3.gtpu_teid &&
	       dr_matcher_supp_tnl_gtpu_teid(&dmn->info.caps);
}

static int dr_matcher_supp_tnl_gtpu_dw_2(struct dr_devx_caps *caps)
{
	return caps->flex_protocols & MLX5_FLEX_PARSER_GTPU_DW_2_ENABLED;
}

static bool dr_mask_is_tnl_gtpu_dw_2(struct dr_match_param *mask,
				     struct mlx5dv_dr_domain *dmn)
{
	return mask->misc3.gtpu_dw_2 &&
	       dr_matcher_supp_tnl_gtpu_dw_2(&dmn->info.caps);
}

static int dr_matcher_supp_tnl_gtpu_first_ext(struct dr_devx_caps *caps)
{
	return caps->flex_protocols & MLX5_FLEX_PARSER_GTPU_FIRST_EXT_DW_0_ENABLED;
}

static bool dr_mask_is_tnl_gtpu_first_ext(struct dr_match_param *mask,
					  struct mlx5dv_dr_domain *dmn)
{
	return mask->misc3.gtpu_first_ext_dw_0 &&
	       dr_matcher_supp_tnl_gtpu_first_ext(&dmn->info.caps);
}

static bool dr_mask_is_tnl_gtpu_flex_parser_0(struct dr_match_param *mask,
					      struct mlx5dv_dr_domain *dmn)
{
	struct dr_devx_caps *caps = &dmn->info.caps;

	return ((caps->flex_parser_id_gtpu_dw_0 <= DR_STE_MAX_FLEX_0_ID) &&
		dr_mask_is_tnl_gtpu_dw_0(mask, dmn)) ||
	       ((caps->flex_parser_id_gtpu_teid <= DR_STE_MAX_FLEX_0_ID) &&
		dr_mask_is_tnl_gtpu_teid(mask, dmn)) ||
	       ((caps->flex_parser_id_gtpu_dw_2 <= DR_STE_MAX_FLEX_0_ID) &&
		dr_mask_is_tnl_gtpu_dw_2(mask, dmn)) ||
	       ((caps->flex_parser_id_gtpu_first_ext_dw_0 <= DR_STE_MAX_FLEX_0_ID) &&
		dr_mask_is_tnl_gtpu_first_ext(mask, dmn));
}

static bool dr_mask_is_tnl_gtpu_flex_parser_1(struct dr_match_param *mask,
					      struct mlx5dv_dr_domain *dmn)
{
	struct dr_devx_caps *caps = &dmn->info.caps;

	return ((caps->flex_parser_id_gtpu_dw_0 > DR_STE_MAX_FLEX_0_ID) &&
		dr_mask_is_tnl_gtpu_dw_0(mask, dmn)) ||
	       ((caps->flex_parser_id_gtpu_teid > DR_STE_MAX_FLEX_0_ID) &&
		dr_mask_is_tnl_gtpu_teid(mask, dmn)) ||
	       ((caps->flex_parser_id_gtpu_dw_2 > DR_STE_MAX_FLEX_0_ID) &&
		dr_mask_is_tnl_gtpu_dw_2(mask, dmn)) ||
	       ((caps->flex_parser_id_gtpu_first_ext_dw_0 > DR_STE_MAX_FLEX_0_ID) &&
		dr_mask_is_tnl_gtpu_first_ext(mask, dmn));
}

static bool dr_mask_is_tnl_gtpu_any(struct dr_match_param *mask,
				    struct mlx5dv_dr_domain *dmn)
{
	return dr_mask_is_tnl_gtpu_flex_parser_0(mask, dmn) ||
	       dr_mask_is_tnl_gtpu_flex_parser_1(mask, dmn) ||
	       dr_mask_is_tnl_gtpu(mask, dmn);
}

static inline int dr_matcher_supp_icmp_v4(struct dr_devx_caps *caps)
{
	return (caps->sw_format_ver == MLX5_HW_CONNECTX_6DX) ||
	       (caps->flex_protocols & MLX5_FLEX_PARSER_ICMP_V4_ENABLED);
}

static inline int dr_matcher_supp_icmp_v6(struct dr_devx_caps *caps)
{
	return (caps->sw_format_ver == MLX5_HW_CONNECTX_6DX) ||
	       (caps->flex_protocols & MLX5_FLEX_PARSER_ICMP_V6_ENABLED);
}

static bool dr_mask_is_icmpv6_set(struct dr_match_misc3 *misc3)
{
	return (misc3->icmpv6_type || misc3->icmpv6_code ||
		misc3->icmpv6_header_data);
}

static bool dr_mask_is_icmp(struct dr_match_param *mask,
			    struct mlx5dv_dr_domain *dmn)
{
	if (DR_MASK_IS_ICMPV4_SET(&mask->misc3))
		return dr_matcher_supp_icmp_v4(&dmn->info.caps);
	else if (dr_mask_is_icmpv6_set(&mask->misc3))
		return dr_matcher_supp_icmp_v6(&dmn->info.caps);

	return false;
}

static bool dr_mask_is_wqe_metadata_set(struct dr_match_misc2 *misc2)
{
	return misc2->metadata_reg_a;
}

static bool dr_mask_is_reg_c_0_3_set(struct dr_match_misc2 *misc2)
{
	return (misc2->metadata_reg_c_0 || misc2->metadata_reg_c_1 ||
		misc2->metadata_reg_c_2 || misc2->metadata_reg_c_3);
}

static bool dr_mask_is_reg_c_4_7_set(struct dr_match_misc2 *misc2)
{
	return (misc2->metadata_reg_c_4 || misc2->metadata_reg_c_5 ||
		misc2->metadata_reg_c_6 || misc2->metadata_reg_c_7);
}

static bool dr_mask_is_gvmi_or_qpn_set(struct dr_match_misc *misc)
{
	return (misc->source_sqn || misc->source_port);
}

static bool dr_mask_is_flex_parser_id_0_3_set(uint32_t flex_parser_id,
					      uint32_t flex_parser_value)
{
	if (flex_parser_id)
		return flex_parser_id <= DR_STE_MAX_FLEX_0_ID;

	/* Using flex_parser 0 means that id is zero, thus value must be set. */
	return flex_parser_value;
}

static bool dr_mask_is_flex_parser_0_3_set(struct dr_match_misc4 *misc4)
{
	return (dr_mask_is_flex_parser_id_0_3_set(misc4->prog_sample_field_id_0,
			misc4->prog_sample_field_value_0) ||
		dr_mask_is_flex_parser_id_0_3_set(misc4->prog_sample_field_id_1,
			misc4->prog_sample_field_value_1) ||
		dr_mask_is_flex_parser_id_0_3_set(misc4->prog_sample_field_id_2,
			misc4->prog_sample_field_value_2) ||
		dr_mask_is_flex_parser_id_0_3_set(misc4->prog_sample_field_id_3,
			misc4->prog_sample_field_value_3) ||
		dr_mask_is_flex_parser_id_0_3_set(misc4->prog_sample_field_id_4,
			misc4->prog_sample_field_value_4) ||
		dr_mask_is_flex_parser_id_0_3_set(misc4->prog_sample_field_id_5,
			misc4->prog_sample_field_value_5) ||
		dr_mask_is_flex_parser_id_0_3_set(misc4->prog_sample_field_id_6,
			misc4->prog_sample_field_value_6) ||
		dr_mask_is_flex_parser_id_0_3_set(misc4->prog_sample_field_id_7,
			misc4->prog_sample_field_value_7));
}

static bool dr_mask_is_flex_parser_id_4_7_set(uint32_t flex_parser_id)
{
	return flex_parser_id > DR_STE_MAX_FLEX_0_ID &&
	       flex_parser_id <= DR_STE_MAX_FLEX_1_ID;
}

static bool dr_mask_is_flex_parser_4_7_set(struct dr_match_misc4 *misc4)
{
	return (dr_mask_is_flex_parser_id_4_7_set(misc4->prog_sample_field_id_0) ||
		dr_mask_is_flex_parser_id_4_7_set(misc4->prog_sample_field_id_1) ||
		dr_mask_is_flex_parser_id_4_7_set(misc4->prog_sample_field_id_2) ||
		dr_mask_is_flex_parser_id_4_7_set(misc4->prog_sample_field_id_3) ||
		dr_mask_is_flex_parser_id_4_7_set(misc4->prog_sample_field_id_4) ||
		dr_mask_is_flex_parser_id_4_7_set(misc4->prog_sample_field_id_5) ||
		dr_mask_is_flex_parser_id_4_7_set(misc4->prog_sample_field_id_6) ||
		dr_mask_is_flex_parser_id_4_7_set(misc4->prog_sample_field_id_7));
}

static bool dr_mask_is_tunnel_header_0_1_set(struct dr_match_misc5 *misc5)
{
	return misc5->tunnel_header_0 || misc5->tunnel_header_1;
}

static int dr_matcher_supp_tnl_mpls_over_gre(struct dr_devx_caps *caps)
{
	return caps->flex_protocols & MLX5_FLEX_PARSER_MPLS_OVER_GRE_ENABLED;
}

static bool dr_mask_is_tnl_mpls_over_gre(struct dr_match_param *mask,
					 struct mlx5dv_dr_domain *dmn)
{
	return DR_MASK_IS_OUTER_MPLS_OVER_GRE_SET(&mask->misc2) &&
	       dr_matcher_supp_tnl_mpls_over_gre(&dmn->info.caps);
}

static int dr_matcher_supp_tnl_mpls_over_udp(struct dr_devx_caps *caps)
{
	return caps->flex_protocols & mlx5_FLEX_PARSER_MPLS_OVER_UDP_ENABLED;
}

static bool dr_mask_is_tnl_mpls_over_udp(struct dr_match_param *mask,
					 struct mlx5dv_dr_domain *dmn)
{
	return DR_MASK_IS_OUTER_MPLS_OVER_UDP_SET(&mask->misc2) &&
	       dr_matcher_supp_tnl_mpls_over_udp(&dmn->info.caps);
}

static bool dr_matcher_is_mask_consumed(struct dr_match_param *mask)
{
	int i;

	for (i = 0; i < sizeof(struct dr_match_param); i++)
		if (((uint8_t *)mask)[i] != 0)
			return false;

	return true;
}

static void dr_matcher_copy_mask(struct dr_match_param *dst_mask,
				 struct dr_match_param *src_mask,
				 uint8_t match_criteria)
{
	if (match_criteria & DR_MATCHER_CRITERIA_OUTER)
		dst_mask->outer = src_mask->outer;

	if (match_criteria & DR_MATCHER_CRITERIA_MISC)
		dst_mask->misc = src_mask->misc;

	if (match_criteria & DR_MATCHER_CRITERIA_INNER)
		dst_mask->inner = src_mask->inner;

	if (match_criteria & DR_MATCHER_CRITERIA_MISC2)
		dst_mask->misc2 = src_mask->misc2;

	if (match_criteria & DR_MATCHER_CRITERIA_MISC3)
		dst_mask->misc3 = src_mask->misc3;

	if (match_criteria & DR_MATCHER_CRITERIA_MISC4)
		dst_mask->misc4 = src_mask->misc4;

	if (match_criteria & DR_MATCHER_CRITERIA_MISC5)
		dst_mask->misc5 = src_mask->misc5;
}

static void dr_matcher_destroy_definer_objs(struct dr_ste_build *sb,
					    uint8_t idx)
{
	int i;

	for (i = 0; i < idx; i++) {
		mlx5dv_devx_obj_destroy(sb[i].definer_obj);
		sb[i].lu_type = 0;
		sb[i].htbl_type = 0;
		sb[i].definer_obj = NULL;
	}
}

static int dr_matcher_create_definer_objs(struct ibv_context *ctx,
					  struct dr_ste_build *sb,
					  uint8_t idx)
{
	struct mlx5dv_devx_obj *devx_obj;
	int i;

	for (i = 0; i < idx; i++) {
		devx_obj = dr_devx_create_definer(ctx, sb[i].format_id, sb[i].match);
		if (!devx_obj)
			goto cleanup;

		/* The lu_type combines the definer and the entry type */
		sb[i].lu_type |= devx_obj->object_id;
		sb[i].htbl_type = DR_STE_HTBL_TYPE_MATCH;
		sb[i].definer_obj = devx_obj;
	}

	return 0;

cleanup:
	dr_matcher_destroy_definer_objs(sb, i);
	return errno;
}

static void dr_matcher_clear_definers_builders(struct dr_matcher_rx_tx *nic_matcher)
{
	struct dr_ste_build *sb = nic_matcher->ste_builder;
	int i;

	for (i = 0; i < nic_matcher->num_of_builders; i++)
		memset(&sb[i], 0, sizeof(*sb));

	nic_matcher->num_of_builders = 0;
}

static int dr_matcher_set_definer_builders(struct mlx5dv_dr_matcher *matcher,
					   struct dr_matcher_rx_tx *nic_matcher)
{
	struct dr_domain_rx_tx *nic_dmn = nic_matcher->nic_tbl->nic_dmn;
	struct dr_ste_build *sb = nic_matcher->ste_builder;
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	bool rx = nic_dmn->type == DR_DOMAIN_NIC_TYPE_RX;
	struct dr_devx_caps *caps = &dmn->info.caps;
	struct dr_ste_ctx *ste_ctx = dmn->ste_ctx;
	struct dr_match_param mask = {};
	bool src_ipv6, dst_ipv6;
	uint8_t idx = 0;
	uint8_t ipv;
	int ret;

	ipv = matcher->mask.outer.ip_version;
	src_ipv6 = dr_mask_is_src_addr_set(&matcher->mask.outer);
	dst_ipv6 = dr_mask_is_dst_addr_set(&matcher->mask.outer);


	if (caps->definer_format_sup & (1 << DR_MATCHER_DEFINER_0)) {
		dr_matcher_copy_mask(&mask, &matcher->mask, matcher->match_criteria);
		ret = dr_ste_build_def0(ste_ctx, &sb[idx++], &mask, caps, false, rx);
		if (!ret && dr_matcher_is_mask_consumed(&mask))
			goto done;

		memset(sb, 0, sizeof(*sb));
		idx = 0;
	}

	if (dmn->info.caps.definer_format_sup & (1 << DR_MATCHER_DEFINER_2)) {
		dr_matcher_copy_mask(&mask, &matcher->mask, matcher->match_criteria);
		ret = dr_ste_build_def2(ste_ctx, &sb[idx++], &mask, caps, false, rx);
		if (!ret && dr_matcher_is_mask_consumed(&mask))
			goto done;

		memset(sb, 0, sizeof(*sb));
		idx = 0;
	}

	if (caps->definer_format_sup & (1 << DR_MATCHER_DEFINER_16)) {
		dr_matcher_copy_mask(&mask, &matcher->mask, matcher->match_criteria);
		ret = dr_ste_build_def16(ste_ctx, &sb[idx++], &mask, caps, false, rx);
		if (!ret && dr_matcher_is_mask_consumed(&mask))
			goto done;

		memset(sb, 0, sizeof(*sb));
		idx = 0;
	}

	if (caps->definer_format_sup & (1 << DR_MATCHER_DEFINER_22)) {
		dr_matcher_copy_mask(&mask, &matcher->mask, matcher->match_criteria);
		ret = dr_ste_build_def22(ste_ctx, &sb[idx++], &mask, false, rx);
		if (!ret && dr_matcher_is_mask_consumed(&mask))
			goto done;

		memset(sb, 0, sizeof(*sb));
		idx = 0;
	}

	if (caps->definer_format_sup & (1 << DR_MATCHER_DEFINER_24)) {
		dr_matcher_copy_mask(&mask, &matcher->mask, matcher->match_criteria);
		ret = dr_ste_build_def24(ste_ctx, &sb[idx++], &mask, false, rx);
		if (!ret && dr_matcher_is_mask_consumed(&mask))
			goto done;

		memset(sb, 0, sizeof(*sb));
		idx = 0;
	}

	if (caps->definer_format_sup & (1 << DR_MATCHER_DEFINER_25)) {
		dr_matcher_copy_mask(&mask, &matcher->mask, matcher->match_criteria);
		ret = dr_ste_build_def25(ste_ctx, &sb[idx++], &mask, false, rx);
		if (!ret && dr_matcher_is_mask_consumed(&mask))
			goto done;

		memset(sb, 0, sizeof(*sb));
		idx = 0;
	}

	if ((ipv == DR_MASK_IP_VERSION_IPV6 && src_ipv6) &&
	    (caps->definer_format_sup & (1 << DR_MATCHER_DEFINER_6)) &&
	    (caps->definer_format_sup & (1 << DR_MATCHER_DEFINER_26))) {
		dr_matcher_copy_mask(&mask, &matcher->mask, matcher->match_criteria);
		ret = dr_ste_build_def26(ste_ctx, &sb[idx++], &mask, false, rx);
		if (!ret && dst_ipv6)
			ret = dr_ste_build_def6(ste_ctx, &sb[idx++], &mask, false, rx);

		if (!ret && dr_matcher_is_mask_consumed(&mask))
			goto done;

		memset(&sb[0], 0, sizeof(*sb));
		memset(&sb[1], 0, sizeof(*sb));
		idx = 0;
	}

	if (dmn->info.caps.definer_format_sup & (1 << DR_MATCHER_DEFINER_28)) {
		dr_matcher_copy_mask(&mask, &matcher->mask, matcher->match_criteria);
		ret = dr_ste_build_def28(ste_ctx, &sb[idx++], &mask, false, rx);
		if (!ret && dr_matcher_is_mask_consumed(&mask))
			goto done;

		memset(sb, 0, sizeof(struct dr_ste_build));
		idx = 0;
	}

	if (dmn->info.caps.definer_format_sup & (1ULL << DR_MATCHER_DEFINER_33)) {
		dr_matcher_copy_mask(&mask, &matcher->mask, matcher->match_criteria);
		ret = dr_ste_build_def33(ste_ctx, &sb[idx++], &mask, false, rx);
		if (!ret && dr_matcher_is_mask_consumed(&mask))
			goto done;

		memset(sb, 0, sizeof(*sb));
		idx = 0;
	}

	return ENOTSUP;

done:
	nic_matcher->num_of_builders = idx;
	return 0;
}

static bool dr_matcher_is_definer_support_mq(struct dr_matcher_rx_tx *nic_matcher)
{
	/* ipv6 needs 2 definers and not supported yet */
	if (nic_matcher->num_of_builders == 1 &&
	    nic_matcher->ste_builder->htbl_type == DR_STE_HTBL_TYPE_MATCH)
		return true;

	return false;
}

static int dr_matcher_set_large_ste_builders(struct mlx5dv_dr_matcher *matcher,
					     struct dr_matcher_rx_tx *nic_matcher)
{
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	int ret;

	if (dmn->info.caps.sw_format_ver != MLX5_HW_CONNECTX_6DX ||
	    !dmn->info.caps.definer_format_sup)
		return ENOTSUP;

	ret = dr_matcher_set_definer_builders(matcher, nic_matcher);
	if (ret)
		return ret;

	ret = dr_matcher_create_definer_objs(dmn->ctx,
					     nic_matcher->ste_builder,
					     nic_matcher->num_of_builders);
	if (ret)
		goto clear_definers_builders;

	return 0;

clear_definers_builders:
	dr_matcher_clear_definers_builders(nic_matcher);
	return ret;
}

static void dr_matcher_clear_ste_builders(struct dr_matcher_rx_tx *nic_matcher)
{
	if (nic_matcher->ste_builder->htbl_type == DR_STE_HTBL_TYPE_MATCH)
		dr_matcher_destroy_definer_objs(nic_matcher->ste_builder,
						nic_matcher->num_of_builders);
}

static int dr_matcher_set_ste_builders(struct mlx5dv_dr_matcher *matcher,
				       struct dr_matcher_rx_tx *nic_matcher)
{
	struct dr_domain_rx_tx *nic_dmn = nic_matcher->nic_tbl->nic_dmn;
	struct dr_ste_build *sb = nic_matcher->ste_builder;
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	struct dr_ste_ctx *ste_ctx = dmn->ste_ctx;
	struct dr_match_param mask = {};
	bool allow_empty_match = false;
	bool inner, rx;
	uint8_t ipv;
	int idx = 0;
	int ret;

	ret = dr_ste_build_pre_check(dmn, matcher->match_criteria,
				     &matcher->mask, NULL);
	if (ret)
		return ret;

	/* Use a large definers for matching if possible */
	ret = dr_matcher_set_large_ste_builders(matcher, nic_matcher);
	if (!ret)
		return 0;

	/* Create a temporary mask to track and clear used mask fields */
	dr_matcher_copy_mask(&mask, &matcher->mask, matcher->match_criteria);

	/* Optimize RX pipe by reducing source port match, since
	 * the FDB RX part is connected only to the wire.
	 */
	rx = nic_dmn->type == DR_DOMAIN_NIC_TYPE_RX;
	if (dmn->type == MLX5DV_DR_DOMAIN_TYPE_FDB &&
	    rx && mask.misc.source_port) {
		mask.misc.source_port = 0;
		allow_empty_match = true;
	}

	/* Outer */
	if (matcher->match_criteria & (DR_MATCHER_CRITERIA_OUTER |
				       DR_MATCHER_CRITERIA_MISC |
				       DR_MATCHER_CRITERIA_MISC2 |
				       DR_MATCHER_CRITERIA_MISC3 |
				       DR_MATCHER_CRITERIA_MISC5)) {
		inner = false;
		ipv = mask.outer.ip_version;

		if (dr_mask_is_wqe_metadata_set(&mask.misc2))
			dr_ste_build_general_purpose(ste_ctx, &sb[idx++],
						     &mask, inner, rx);

		if (dr_mask_is_reg_c_0_3_set(&mask.misc2))
			dr_ste_build_register_0(ste_ctx, &sb[idx++],
						&mask, inner, rx);

		if (dr_mask_is_reg_c_4_7_set(&mask.misc2))
			dr_ste_build_register_1(ste_ctx, &sb[idx++],
						&mask, inner, rx);

		if (dr_mask_is_gvmi_or_qpn_set(&mask.misc) &&
		    (dmn->type == MLX5DV_DR_DOMAIN_TYPE_FDB ||
		     dmn->type == MLX5DV_DR_DOMAIN_TYPE_NIC_RX))
			dr_ste_build_src_gvmi_qpn(ste_ctx, &sb[idx++],
						  &mask, &dmn->info.caps,
						  inner, rx);

		if (dr_mask_is_smac_set(&mask.outer) &&
		    dr_mask_is_dmac_set(&mask.outer))
			dr_ste_build_eth_l2_src_dst(ste_ctx, &sb[idx++],
						    &mask, inner, rx);

		if (dr_mask_is_smac_set(&mask.outer))
			dr_ste_build_eth_l2_src(ste_ctx, &sb[idx++],
						&mask, inner, rx);

		if (DR_MASK_IS_L2_DST(mask.outer, mask.misc, outer))
			dr_ste_build_eth_l2_dst(ste_ctx, &sb[idx++],
						&mask, inner, rx);

		if (ipv == 4) {
			if (dr_mask_is_ttl_set(&mask.outer) ||
			    dr_mask_is_ipv4_ihl_set(&mask.outer))
				dr_ste_build_eth_l3_ipv4_misc(ste_ctx, &sb[idx++],
							      &mask, inner, rx);

			if (dr_mask_is_ipv4_5_tuple_set(&mask.outer))
				dr_ste_build_eth_l3_ipv4_5_tuple(ste_ctx, &sb[idx++],
								 &mask, inner, rx);
		} else if (ipv == 6) {
			if (dr_mask_is_dst_addr_set(&mask.outer))
				dr_ste_build_eth_l3_ipv6_dst(ste_ctx, &sb[idx++],
							     &mask, inner, rx);

			if (dr_mask_is_src_addr_set(&mask.outer))
				dr_ste_build_eth_l3_ipv6_src(ste_ctx, &sb[idx++],
							     &mask, inner, rx);

			if (DR_MASK_IS_ETH_L4_SET(mask.outer, mask.misc, outer))
				dr_ste_build_eth_ipv6_l3_l4(ste_ctx, &sb[idx++],
							    &mask, inner, rx);
		}

		if (dr_mask_is_tnl_vxlan_gpe(&mask, dmn)) {
			dr_ste_build_tnl_vxlan_gpe(ste_ctx, &sb[idx++],
						   &mask, inner, rx);
		} else if (dr_mask_is_tnl_geneve(&mask, dmn) ||
			 dr_mask_is_tnl_geneve_tlv_opt(&mask, dmn)) {
			if (dr_mask_is_tnl_geneve(&mask, dmn))
				dr_ste_build_tnl_geneve(ste_ctx, &sb[idx++],
							&mask, inner, rx);

			if (dr_mask_is_tnl_geneve_tlv_opt(&mask, dmn))
				dr_ste_build_tnl_geneve_tlv_opt(ste_ctx, &sb[idx++],
								&mask, &dmn->info.caps,
								inner, rx);
		} else if (dr_mask_is_tnl_gtpu_any(&mask, dmn)) {
			if (dr_mask_is_tnl_gtpu_flex_parser_0(&mask, dmn))
				dr_ste_build_tnl_gtpu_flex_parser_0(ste_ctx, &sb[idx++],
								    &mask, &dmn->info.caps,
								    inner, rx);

			if (dr_mask_is_tnl_gtpu_flex_parser_1(&mask, dmn))
				dr_ste_build_tnl_gtpu_flex_parser_1(ste_ctx, &sb[idx++],
								    &mask, &dmn->info.caps,
								    inner, rx);

			if (dr_mask_is_tnl_gtpu(&mask, dmn))
				dr_ste_build_tnl_gtpu(ste_ctx, &sb[idx++],
						      &mask, inner, rx);
		} else if (dr_mask_is_tunnel_header_0_1_set(&mask.misc5)) {
			dr_ste_build_tunnel_header_0_1(ste_ctx, &sb[idx++],
						       &mask, false, rx);
		}

		if (DR_MASK_IS_ETH_L4_MISC_SET(mask.misc3, outer))
			dr_ste_build_eth_l4_misc(ste_ctx, &sb[idx++],
						 &mask, inner, rx);

		if (DR_MASK_IS_FIRST_MPLS_SET(mask.misc2, outer))
			dr_ste_build_mpls(ste_ctx, &sb[idx++],
					  &mask, inner, rx);

		if (dr_mask_is_tnl_mpls_over_gre(&mask, dmn))
			dr_ste_build_tnl_mpls_over_gre(ste_ctx, &sb[idx++],
						       &mask, &dmn->info.caps,
						       inner, rx);
		else if (dr_mask_is_tnl_mpls_over_udp(&mask, dmn))
			dr_ste_build_tnl_mpls_over_udp(ste_ctx, &sb[idx++],
						       &mask, &dmn->info.caps,
						       inner, rx);

		if (dr_mask_is_icmp(&mask, dmn))
			dr_ste_build_icmp(ste_ctx, &sb[idx++],
					  &mask, &dmn->info.caps,
					  inner, rx);

		if (dr_mask_is_tnl_gre_set(&mask.misc))
			dr_ste_build_tnl_gre(ste_ctx, &sb[idx++], &mask, inner, rx);
	}

	/* Inner */
	if (matcher->match_criteria & (DR_MATCHER_CRITERIA_INNER |
				       DR_MATCHER_CRITERIA_MISC |
				       DR_MATCHER_CRITERIA_MISC2 |
				       DR_MATCHER_CRITERIA_MISC3)) {
		inner = true;
		ipv = mask.inner.ip_version;

		if (dr_mask_is_eth_l2_tnl_set(&mask.misc))
			dr_ste_build_eth_l2_tnl(ste_ctx, &sb[idx++], &mask,
						inner, rx);

		if (dr_mask_is_smac_set(&mask.inner) &&
		    dr_mask_is_dmac_set(&mask.inner))
			dr_ste_build_eth_l2_src_dst(ste_ctx, &sb[idx++],
						    &mask, inner, rx);

		if (dr_mask_is_smac_set(&mask.inner))
			dr_ste_build_eth_l2_src(ste_ctx, &sb[idx++],
						&mask, inner, rx);

		if (DR_MASK_IS_L2_DST(mask.inner, mask.misc, inner))
			dr_ste_build_eth_l2_dst(ste_ctx, &sb[idx++],
						&mask, inner, rx);

		if (ipv == 4) {
			if (dr_mask_is_ttl_set(&mask.inner) ||
			    dr_mask_is_ipv4_ihl_set(&mask.inner))
				dr_ste_build_eth_l3_ipv4_misc(ste_ctx, &sb[idx++],
							      &mask, inner, rx);

			if (dr_mask_is_ipv4_5_tuple_set(&mask.inner))
				dr_ste_build_eth_l3_ipv4_5_tuple(ste_ctx, &sb[idx++],
								 &mask, inner, rx);
		} else if (ipv == 6) {
			if (dr_mask_is_dst_addr_set(&mask.inner))
				dr_ste_build_eth_l3_ipv6_dst(ste_ctx, &sb[idx++],
							     &mask, inner, rx);

			if (dr_mask_is_src_addr_set(&mask.inner))
				dr_ste_build_eth_l3_ipv6_src(ste_ctx, &sb[idx++],
							     &mask,  inner, rx);

			if (DR_MASK_IS_ETH_L4_SET(mask.inner, mask.misc, inner))
				dr_ste_build_eth_ipv6_l3_l4(ste_ctx, &sb[idx++],
							    &mask, inner, rx);
		}

		if (DR_MASK_IS_ETH_L4_MISC_SET(mask.misc3, inner))
			dr_ste_build_eth_l4_misc(ste_ctx, &sb[idx++],
						 &mask, inner, rx);

		if (DR_MASK_IS_FIRST_MPLS_SET(mask.misc2, inner))
			dr_ste_build_mpls(ste_ctx, &sb[idx++],
					  &mask, inner, rx);

		if (dr_mask_is_tnl_mpls_over_gre(&mask, dmn))
			dr_ste_build_tnl_mpls_over_gre(ste_ctx, &sb[idx++],
						       &mask, &dmn->info.caps,
						       inner, rx);
		else if (dr_mask_is_tnl_mpls_over_udp(&mask, dmn))
			dr_ste_build_tnl_mpls_over_udp(ste_ctx, &sb[idx++],
						       &mask, &dmn->info.caps,
						       inner, rx);
	}

	if (matcher->match_criteria & DR_MATCHER_CRITERIA_MISC4) {
		if (dr_mask_is_flex_parser_0_3_set(&mask.misc4))
			dr_ste_build_flex_parser_0(ste_ctx, &sb[idx++],
						   &mask, false, rx);

		if (dr_mask_is_flex_parser_4_7_set(&mask.misc4))
			dr_ste_build_flex_parser_1(ste_ctx, &sb[idx++],
						   &mask, false, rx);
	}

	/* Empty matcher, takes all */
	if ((!idx && allow_empty_match) ||
	    matcher->match_criteria == DR_MATCHER_CRITERIA_EMPTY)
		dr_ste_build_empty_always_hit(&sb[idx++], rx);

	if (idx == 0) {
		dr_dbg(dmn, "Cannot generate any valid rules from mask\n");
		errno = EINVAL;
		return errno;
	}

	/* Check that all mask fields were consumed */
	if (!dr_matcher_is_mask_consumed(&mask)) {
		dr_dbg(dmn, "Mask contains unsupported parameters\n");
		errno = EOPNOTSUPP;
		return errno;
	}

	nic_matcher->num_of_builders = idx;

	return 0;
}

static int dr_matcher_connect(struct mlx5dv_dr_domain *dmn,
			      struct dr_matcher_rx_tx *curr_nic_matcher,
			      struct dr_matcher_rx_tx *next_nic_matcher,
			      struct dr_matcher_rx_tx *prev_nic_matcher)
{
	struct dr_table_rx_tx *nic_tbl = curr_nic_matcher->nic_tbl;
	struct dr_domain_rx_tx *nic_dmn = nic_tbl->nic_dmn;
	struct dr_htbl_connect_info info;
	struct dr_ste_htbl *prev_htbl;
	int ret;

	/* Connect end anchor hash table to next_htbl or to the default address */
	if (next_nic_matcher) {
		info.type = CONNECT_HIT;
		info.hit_next_htbl = next_nic_matcher->s_htbl;
	} else {
		info.type = CONNECT_MISS;
		info.miss_icm_addr = nic_dmn->default_icm_addr;
	}
	ret = dr_ste_htbl_init_and_postsend(dmn, nic_dmn,
					    curr_nic_matcher->e_anchor,
					    &info, info.type == CONNECT_HIT, 0);
	if (ret)
		return ret;

	/* Connect start hash table to end anchor */
	info.type = CONNECT_MISS;
	info.miss_icm_addr = curr_nic_matcher->e_anchor->chunk->icm_addr;
	ret = dr_ste_htbl_init_and_postsend(dmn, nic_dmn,
					    curr_nic_matcher->s_htbl,
					    &info, false, 0);
	if (ret)
		return ret;

	/* Connect previous hash table to matcher start hash table */
	if (prev_nic_matcher)
		prev_htbl = prev_nic_matcher->e_anchor;
	else
		prev_htbl = nic_tbl->s_anchor;

	info.type = CONNECT_HIT;
	info.hit_next_htbl = curr_nic_matcher->s_htbl;
	ret = dr_ste_htbl_init_and_postsend(dmn, nic_dmn, prev_htbl,
					    &info, true, 0);
	if (ret)
		return ret;

	/* Update the pointing ste and next hash table */
	curr_nic_matcher->s_htbl->pointing_ste = prev_htbl->ste_arr;
	prev_htbl->ste_arr[0].next_htbl = curr_nic_matcher->s_htbl;

	if (next_nic_matcher) {
		next_nic_matcher->s_htbl->pointing_ste = curr_nic_matcher->e_anchor->ste_arr;
		curr_nic_matcher->e_anchor->ste_arr[0].next_htbl = next_nic_matcher->s_htbl;
	}

	return 0;
}

static int dr_matcher_add_to_tbl(struct mlx5dv_dr_matcher *matcher)
{
	struct mlx5dv_dr_matcher *next_matcher, *prev_matcher, *tmp_matcher;
	struct mlx5dv_dr_table *tbl = matcher->tbl;
	struct mlx5dv_dr_domain *dmn = tbl->dmn;
	int ret;

	if (dr_is_root_table(matcher->tbl))
		return 0;

	next_matcher = NULL;

	list_for_each(&tbl->matcher_list, tmp_matcher, matcher_list)
		if (tmp_matcher->prio >= matcher->prio) {
			next_matcher = tmp_matcher;
			break;
		}

	if (next_matcher)
		prev_matcher = list_prev(&tbl->matcher_list,
					 next_matcher,
					 matcher_list);
	else
		prev_matcher = list_tail(&tbl->matcher_list,
					 struct mlx5dv_dr_matcher,
					 matcher_list);

	if (dmn->type == MLX5DV_DR_DOMAIN_TYPE_FDB ||
	    dmn->type == MLX5DV_DR_DOMAIN_TYPE_NIC_RX) {
		ret = dr_matcher_connect(dmn, &matcher->rx,
					 next_matcher ? &next_matcher->rx : NULL,
					 prev_matcher ?	&prev_matcher->rx : NULL);
		if (ret)
			return ret;
	}

	if (dmn->type == MLX5DV_DR_DOMAIN_TYPE_FDB ||
	    dmn->type == MLX5DV_DR_DOMAIN_TYPE_NIC_TX) {
		ret = dr_matcher_connect(dmn, &matcher->tx,
					 next_matcher ? &next_matcher->tx : NULL,
					 prev_matcher ?	&prev_matcher->tx : NULL);
		if (ret)
			return ret;
	}

	if (prev_matcher)
		list_add_after(&tbl->matcher_list,
			       &prev_matcher->matcher_list,
			       &matcher->matcher_list);
	else if (next_matcher)
		list_add_before(&tbl->matcher_list,
				&next_matcher->matcher_list,
				&matcher->matcher_list);
	else
		list_add(&tbl->matcher_list, &matcher->matcher_list);

	return 0;
}

static void dr_matcher_uninit_nic(struct dr_matcher_rx_tx *nic_matcher)
{
	dr_matcher_clear_ste_builders(nic_matcher);
	dr_htbl_put(nic_matcher->s_htbl);
	dr_htbl_put(nic_matcher->e_anchor);
}

static void dr_matcher_uninit_fdb(struct mlx5dv_dr_matcher *matcher)
{
	dr_matcher_uninit_nic(&matcher->rx);
	dr_matcher_uninit_nic(&matcher->tx);
}

static int dr_matcher_uninit_root(struct mlx5dv_dr_matcher *matcher)
{
	return mlx5dv_destroy_flow_matcher(matcher->dv_matcher);
}

static void dr_matcher_uninit(struct mlx5dv_dr_matcher *matcher)
{
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;

	if (dr_is_root_table(matcher->tbl)) {
		dr_matcher_uninit_root(matcher);
		return;
	}

	switch (dmn->type) {
	case MLX5DV_DR_DOMAIN_TYPE_NIC_RX:
		dr_matcher_uninit_nic(&matcher->rx);
		break;
	case MLX5DV_DR_DOMAIN_TYPE_NIC_TX:
		dr_matcher_uninit_nic(&matcher->tx);
		break;
	case MLX5DV_DR_DOMAIN_TYPE_FDB:
		dr_matcher_uninit_fdb(matcher);
		break;
	default:
		assert(false);
		break;
	}
}

static int dr_matcher_init_nic(struct mlx5dv_dr_matcher *matcher,
			       struct dr_matcher_rx_tx *nic_matcher)
{
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	int ret;

	ret = dr_matcher_set_ste_builders(matcher, nic_matcher);
	if (ret)
		return ret;

	nic_matcher->e_anchor = dr_ste_htbl_alloc(dmn->ste_icm_pool,
						  DR_CHUNK_SIZE_1,
						  DR_STE_HTBL_TYPE_LEGACY,
						  DR_STE_LU_TYPE_DONT_CARE,
						  0);
	if (!nic_matcher->e_anchor)
		goto clear_ste_builders;

	nic_matcher->s_htbl = dr_ste_htbl_alloc(dmn->ste_icm_pool,
						DR_CHUNK_SIZE_1,
						nic_matcher->ste_builder->htbl_type,
						nic_matcher->ste_builder->lu_type,
						nic_matcher->ste_builder->byte_mask);
	if (!nic_matcher->s_htbl)
		goto free_e_htbl;

	/* make sure the tables exist while empty */
	dr_htbl_get(nic_matcher->s_htbl);
	dr_htbl_get(nic_matcher->e_anchor);

	return 0;

free_e_htbl:
	dr_ste_htbl_free(nic_matcher->e_anchor);
clear_ste_builders:
	dr_matcher_clear_ste_builders(nic_matcher);
	return errno;
}

static int dr_matcher_init_fdb(struct mlx5dv_dr_matcher *matcher)
{
	int ret;

	ret = dr_matcher_init_nic(matcher, &matcher->rx);
	if (ret)
		return ret;

	ret = dr_matcher_init_nic(matcher, &matcher->tx);
	if (ret)
		goto uninit_nic_rx;

	return 0;

uninit_nic_rx:
	dr_matcher_uninit_nic(&matcher->rx);
	return ret;
}

static int dr_matcher_init_root(struct mlx5dv_dr_matcher *matcher,
				struct mlx5dv_flow_match_parameters *mask)
{
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	struct mlx5dv_flow_matcher_attr attr = {};
	enum mlx5dv_flow_table_type type;

	if (dmn->type == MLX5DV_DR_DOMAIN_TYPE_NIC_RX)
		type = MLX5_IB_UAPI_FLOW_TABLE_TYPE_NIC_RX;
	else if (dmn->type == MLX5DV_DR_DOMAIN_TYPE_NIC_TX)
		type = MLX5_IB_UAPI_FLOW_TABLE_TYPE_NIC_TX;
	else
		type = MLX5_IB_UAPI_FLOW_TABLE_TYPE_FDB;

	attr.match_mask = mask;
	attr.priority = matcher->prio;
	attr.type = IBV_FLOW_ATTR_NORMAL;
	attr.match_criteria_enable = matcher->match_criteria;
	attr.ft_type = type;
	attr.comp_mask = MLX5DV_FLOW_MATCHER_MASK_FT_TYPE;

	matcher->dv_matcher = mlx5dv_create_flow_matcher(dmn->ctx, &attr);
	if (!matcher->dv_matcher)
		return errno;

	return 0;
}

static bool dr_matcher_is_fixed_size(struct mlx5dv_dr_matcher *matcher)
{
	return (matcher->rx.fixed_size || matcher->tx.fixed_size);
}

static int dr_matcher_init(struct mlx5dv_dr_matcher *matcher,
			   struct mlx5dv_flow_match_parameters *mask)
{
	struct mlx5dv_dr_table *tbl = matcher->tbl;
	struct mlx5dv_dr_domain *dmn = tbl->dmn;
	int ret;

	if (dr_is_root_table(matcher->tbl))
		return dr_matcher_init_root(matcher, mask);

	if (matcher->match_criteria >= DR_MATCHER_CRITERIA_MAX) {
		dr_dbg(dmn, "Invalid match criteria attribute\n");
		errno = EINVAL;
		return errno;
	}

	if (mask) {
		if (mask->match_sz > DEVX_ST_SZ_BYTES(dr_match_param)) {
			dr_dbg(dmn, "Invalid match size attribute\n");
			errno = EINVAL;
			return errno;
		}
		dr_ste_copy_param(matcher->match_criteria, &matcher->mask, mask);
	}

	switch (dmn->type) {
	case MLX5DV_DR_DOMAIN_TYPE_NIC_RX:
		matcher->rx.nic_tbl = &tbl->rx;
		ret = dr_matcher_init_nic(matcher, &matcher->rx);
		break;
	case MLX5DV_DR_DOMAIN_TYPE_NIC_TX:
		matcher->tx.nic_tbl = &tbl->tx;
		ret = dr_matcher_init_nic(matcher, &matcher->tx);
		break;
	case MLX5DV_DR_DOMAIN_TYPE_FDB:
		matcher->rx.nic_tbl = &tbl->rx;
		matcher->tx.nic_tbl = &tbl->tx;
		ret = dr_matcher_init_fdb(matcher);
		break;
	default:
		assert(false);
		errno = EINVAL;
		return errno;
	}

	/* Drain QP to resolve possible race between new multi QP rules
	 * and matcher hash table initial creation.
	 */
	if (dr_matcher_is_fixed_size(matcher))
		dr_send_ring_force_drain(dmn);

	return ret;
}

static int
dr_matcher_set_nic_matcher_layout(struct mlx5dv_dr_matcher *matcher,
				  struct dr_matcher_rx_tx *nic_matcher,
				  struct mlx5dv_dr_matcher_layout *matcher_layout)
{
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	int ret = 0;

	if (!dr_matcher_is_definer_support_mq(nic_matcher)) {
		dr_dbg(dmn, "not supported not a definer\n");
		errno = ENOTSUP;
		return ENOTSUP;
	}

	dr_domain_lock(dmn);

	if (matcher_layout->flags & MLX5DV_DR_MATCHER_LAYOUT_NUM_RULE) {
		/* if needed set dmn->info.max_log_sw_icm_sz and pool max_log_chunk_sz */
		dr_domain_set_max_ste_icm_size(dmn, matcher_layout->log_num_of_rules_hint);

		ret = dr_rule_rehash_matcher_s_anchor(matcher, nic_matcher,
						      matcher_layout->log_num_of_rules_hint);
		if (ret) {
			dr_dbg(dmn, "failed rehash with log-size: %d\n",
			       matcher_layout->log_num_of_rules_hint);
			goto out;
		}
	}

	if (matcher_layout->flags & MLX5DV_DR_MATCHER_LAYOUT_RESIZABLE) {
		nic_matcher->fixed_size = false;
	} else {
		nic_matcher->fixed_size = true;
		dmn->info.use_mqs = true;
	}

	dr_send_ring_force_drain(dmn);
out:
	dr_domain_unlock(dmn);
	return ret;
}

int mlx5dv_dr_matcher_set_layout(struct mlx5dv_dr_matcher *matcher,
				 struct mlx5dv_dr_matcher_layout *matcher_layout)
{
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	int ret = 0;

	if (dr_is_root_table(matcher->tbl)) {
		dr_dbg(dmn, "Not supported in root table\n");
		errno = ENOTSUP;
		return ENOTSUP;
	}
	if (!check_comp_mask(matcher_layout->flags,
			 MLX5DV_DR_MATCHER_LAYOUT_RESIZABLE |
			 MLX5DV_DR_MATCHER_LAYOUT_NUM_RULE)) {
		dr_dbg(dmn, "Not supported flags 0x%x\n", matcher_layout->flags);
		errno = ENOTSUP;
		return ENOTSUP;
	}

	if ((matcher_layout->flags & MLX5DV_DR_MATCHER_LAYOUT_NUM_RULE) &&
	    !dr_domain_is_support_ste_icm_size(dmn, matcher_layout->log_num_of_rules_hint)) {
		dr_dbg(dmn, "the size is too big: %d\n",
		       matcher_layout->log_num_of_rules_hint);
		errno = ENOTSUP;
		return ENOTSUP;
	}

	if (dmn->type == MLX5DV_DR_DOMAIN_TYPE_NIC_RX ||
	    dmn->type == MLX5DV_DR_DOMAIN_TYPE_FDB) {
		ret = dr_matcher_set_nic_matcher_layout(matcher,
							&matcher->rx,
							matcher_layout);
	}
	if (!ret && (dmn->type == MLX5DV_DR_DOMAIN_TYPE_NIC_TX ||
		     dmn->type == MLX5DV_DR_DOMAIN_TYPE_FDB)) {
		ret = dr_matcher_set_nic_matcher_layout(matcher,
							&matcher->tx,
							matcher_layout);
	}

	if (ret) {
		dr_dbg(dmn, "failed nic (%d) rehash with log-size: %d\n",
		       dmn->type, matcher_layout->log_num_of_rules_hint);
		return ret;
	}

	return 0;
}

struct mlx5dv_dr_matcher *
mlx5dv_dr_matcher_create(struct mlx5dv_dr_table *tbl,
			 uint16_t priority,
			 uint8_t match_criteria_enable,
			 struct mlx5dv_flow_match_parameters *mask)
{
	struct mlx5dv_dr_matcher *matcher;
	int ret;

	atomic_fetch_add(&tbl->refcount, 1);

	matcher = calloc(1, sizeof(*matcher));
	if (!matcher) {
		errno = ENOMEM;
		goto dec_ref;
	}

	matcher->tbl = tbl;
	matcher->prio = priority;
	matcher->match_criteria = match_criteria_enable;
	atomic_init(&matcher->refcount, 1);
	list_node_init(&matcher->matcher_list);
	list_head_init(&matcher->rule_list);

	dr_domain_lock(tbl->dmn);

	ret = dr_matcher_init(matcher, mask);
	if (ret)
		goto free_matcher;

	ret = dr_matcher_add_to_tbl(matcher);
	if (ret)
		goto matcher_uninit;

	dr_domain_unlock(tbl->dmn);

	return matcher;

matcher_uninit:
	dr_matcher_uninit(matcher);
free_matcher:
	dr_domain_unlock(tbl->dmn);
	free(matcher);
dec_ref:
	atomic_fetch_sub(&tbl->refcount, 1);
	return NULL;
}

static int dr_matcher_disconnect(struct mlx5dv_dr_domain *dmn,
				 struct dr_table_rx_tx *nic_tbl,
				 struct dr_matcher_rx_tx *next_nic_matcher,
				 struct dr_matcher_rx_tx *prev_nic_matcher)
{
	struct dr_domain_rx_tx *nic_dmn = nic_tbl->nic_dmn;
	struct dr_htbl_connect_info info;
	struct dr_ste_htbl *prev_anchor;

	if (prev_nic_matcher)
		prev_anchor = prev_nic_matcher->e_anchor;
	else
		prev_anchor = nic_tbl->s_anchor;

	/* Connect previous anchor hash table to next matcher or to the default address */
	if (next_nic_matcher) {
		info.type = CONNECT_HIT;
		info.hit_next_htbl = next_nic_matcher->s_htbl;
		next_nic_matcher->s_htbl->pointing_ste = prev_anchor->ste_arr;
		prev_anchor->ste_arr[0].next_htbl = next_nic_matcher->s_htbl;
	} else {
		info.type = CONNECT_MISS;
		info.miss_icm_addr = nic_dmn->default_icm_addr;
		prev_anchor->ste_arr[0].next_htbl = NULL;
	}

	return dr_ste_htbl_init_and_postsend(dmn, nic_dmn, prev_anchor,
					     &info, true, 0);
}

static int dr_matcher_remove_from_tbl(struct mlx5dv_dr_matcher *matcher)
{
	struct mlx5dv_dr_matcher *prev_matcher, *next_matcher;
	struct mlx5dv_dr_table *tbl = matcher->tbl;
	struct mlx5dv_dr_domain *dmn = tbl->dmn;
	int ret = 0;

	if (dr_is_root_table(matcher->tbl))
		return 0;

	prev_matcher = list_prev(&tbl->matcher_list, matcher, matcher_list);
	next_matcher = list_next(&tbl->matcher_list, matcher, matcher_list);

	if (dmn->type == MLX5DV_DR_DOMAIN_TYPE_FDB ||
	    dmn->type == MLX5DV_DR_DOMAIN_TYPE_NIC_RX) {
		ret = dr_matcher_disconnect(dmn, &tbl->rx,
					    next_matcher ? &next_matcher->rx : NULL,
					    prev_matcher ? &prev_matcher->rx : NULL);
		if (ret)
			return ret;
	}

	if (dmn->type == MLX5DV_DR_DOMAIN_TYPE_FDB ||
	    dmn->type == MLX5DV_DR_DOMAIN_TYPE_NIC_TX) {
		ret = dr_matcher_disconnect(dmn, &tbl->tx,
					    next_matcher ? &next_matcher->tx : NULL,
					    prev_matcher ? &prev_matcher->tx : NULL);
		if (ret)
			return ret;
	}

	list_del(&matcher->matcher_list);

	return 0;
}

int mlx5dv_dr_matcher_destroy(struct mlx5dv_dr_matcher *matcher)
{
	struct mlx5dv_dr_table *tbl = matcher->tbl;

	if (atomic_load(&matcher->refcount) > 1)
		return EBUSY;

	dr_domain_lock(tbl->dmn);

	dr_matcher_remove_from_tbl(matcher);
	dr_matcher_uninit(matcher);
	atomic_fetch_sub(&matcher->tbl->refcount, 1);

	dr_domain_unlock(tbl->dmn);

	free(matcher);

	return 0;
}
