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

#define DR_STE_CALC_LU_TYPE(lookup_type, rx, inner) \
	((inner) ? DR_STE_LU_TYPE_##lookup_type##_I : \
		   (rx) ? DR_STE_LU_TYPE_##lookup_type##_D : \
			  DR_STE_LU_TYPE_##lookup_type##_O)

static void dr_ste_v0_build_eth_l2_src_dst_bit_mask(struct dr_match_param *value,
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

static void dr_ste_v0_build_eth_l3_ipv6_dst_bit_mask(struct dr_match_param *value,
						     bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;

	DR_STE_SET_MASK_V(eth_l3_ipv6_dst, bit_mask, dst_ip_127_96, mask, dst_ip_127_96);
	DR_STE_SET_MASK_V(eth_l3_ipv6_dst, bit_mask, dst_ip_95_64, mask, dst_ip_95_64);
	DR_STE_SET_MASK_V(eth_l3_ipv6_dst, bit_mask, dst_ip_63_32, mask, dst_ip_63_32);
	DR_STE_SET_MASK_V(eth_l3_ipv6_dst, bit_mask, dst_ip_31_0, mask, dst_ip_31_0);
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
	dr_ste_v0_build_eth_l3_ipv6_dst_bit_mask(mask, sb->inner, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL3_IPV6_DST, sb->rx, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_eth_l3_ipv6_dst_tag;
}

static void dr_ste_v0_build_eth_l3_ipv6_src_bit_mask(struct dr_match_param *value,
						     bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;

	DR_STE_SET_MASK_V(eth_l3_ipv6_src, bit_mask, src_ip_127_96, mask, src_ip_127_96);
	DR_STE_SET_MASK_V(eth_l3_ipv6_src, bit_mask, src_ip_95_64, mask, src_ip_95_64);
	DR_STE_SET_MASK_V(eth_l3_ipv6_src, bit_mask, src_ip_63_32, mask, src_ip_63_32);
	DR_STE_SET_MASK_V(eth_l3_ipv6_src, bit_mask, src_ip_31_0, mask, src_ip_31_0);
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
	dr_ste_v0_build_eth_l3_ipv6_src_bit_mask(mask, sb->inner, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL3_IPV6_SRC, sb->rx, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_eth_l3_ipv6_src_tag;
}

static void dr_ste_v0_build_eth_l3_ipv4_5_tuple_bit_mask(struct dr_match_param *value,
							 bool inner, uint8_t *bit_mask)
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
	dr_ste_v0_build_eth_l3_ipv4_5_tuple_bit_mask(mask, sb->inner, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL3_IPV4_5_TUPLE, sb->rx, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_eth_l3_ipv4_5_tuple_tag;
}

static void dr_ste_v0_build_eth_l2_src_or_dst_bit_mask(struct dr_match_param *value,
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

	DR_STE_SET_MASK_V(eth_l2_src, bit_mask, smac_47_16, mask, smac_47_16);
	DR_STE_SET_MASK_V(eth_l2_src, bit_mask, smac_15_0, mask, smac_15_0);

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
						bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;

	DR_STE_SET_MASK_V(eth_l2_dst, bit_mask, dmac_47_16, mask, dmac_47_16);
	DR_STE_SET_MASK_V(eth_l2_dst, bit_mask, dmac_15_0, mask, dmac_15_0);

	dr_ste_v0_build_eth_l2_src_or_dst_bit_mask(value, inner, bit_mask);
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
	dr_ste_v0_build_eth_l2_dst_bit_mask(mask, sb->inner, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL2_DST, sb->rx, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_eth_l2_dst_tag;
}

static void dr_ste_v0_build_eth_l2_tnl_bit_mask(struct dr_match_param *value,
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

	sb->lu_type = DR_STE_LU_TYPE_ETHL2_TUNNELING_I;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_eth_l2_tnl_tag;
}

static void dr_ste_v0_build_eth_l3_ipv4_misc_bit_mask(struct dr_match_param *value,
						      bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;

	DR_STE_SET_MASK_V(eth_l3_ipv4_misc, bit_mask, time_to_live, mask, ip_ttl_hoplimit);
}

static int dr_ste_v0_build_eth_l3_ipv4_misc_tag(struct dr_match_param *value,
						struct dr_ste_build *sb,
						uint8_t *tag)
{
	struct dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l3_ipv4_misc, tag, time_to_live, spec, ip_ttl_hoplimit);

	return 0;
}

static void dr_ste_v0_build_eth_l3_ipv4_misc_init(struct dr_ste_build *sb,
						  struct dr_match_param *mask)
{
	dr_ste_v0_build_eth_l3_ipv4_misc_bit_mask(mask, sb->inner, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL3_IPV4_MISC, sb->rx, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_eth_l3_ipv4_misc_tag;
}

static void dr_ste_v0_build_eth_ipv6_l3_l4_bit_mask(struct dr_match_param *value,
						    bool inner, uint8_t *bit_mask)
{
	struct dr_match_spec *mask = inner ? &value->inner : &value->outer;
	struct dr_match_misc *misc = &value->misc;

	DR_STE_SET_MASK_V(eth_l4, bit_mask, dst_port, mask, tcp_dport);
	DR_STE_SET_MASK_V(eth_l4, bit_mask, src_port, mask, tcp_sport);
	DR_STE_SET_MASK_V(eth_l4, bit_mask, dst_port, mask, udp_dport);
	DR_STE_SET_MASK_V(eth_l4, bit_mask, src_port, mask, udp_sport);
	DR_STE_SET_MASK_V(eth_l4, bit_mask, protocol, mask, ip_protocol);
	DR_STE_SET_MASK_V(eth_l4, bit_mask, fragmented, mask, frag);
	DR_STE_SET_MASK_V(eth_l4, bit_mask, dscp, mask, ip_dscp);
	DR_STE_SET_MASK_V(eth_l4, bit_mask, ecn, mask, ip_ecn);
	DR_STE_SET_MASK_V(eth_l4, bit_mask, ipv6_hop_limit, mask, ip_ttl_hoplimit);

	if (inner)
		DR_STE_SET_MASK_V(eth_l4, bit_mask, flow_label, misc, inner_ipv6_flow_label);
	else
		DR_STE_SET_MASK_V(eth_l4, bit_mask, flow_label, misc, outer_ipv6_flow_label);

	if (mask->tcp_flags) {
		DR_STE_SET_TCP_FLAGS(eth_l4, bit_mask, mask);
		mask->tcp_flags = 0;
	}
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
	dr_ste_v0_build_eth_ipv6_l3_l4_bit_mask(mask, sb->inner, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL4, sb->rx, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_eth_ipv6_l3_l4_tag;
}

static void dr_ste_v0_build_mpls_bit_mask(struct dr_match_param *value,
					  bool inner, uint8_t *bit_mask)
{
	struct dr_match_misc2 *misc2_mask = &value->misc2;

	if (inner)
		DR_STE_SET_MPLS_MASK(mpls, misc2_mask, inner, bit_mask);
	else
		DR_STE_SET_MPLS_MASK(mpls, misc2_mask, outer, bit_mask);
}

static int dr_ste_v0_build_mpls_tag(struct dr_match_param *value,
				    struct dr_ste_build *sb,
				    uint8_t *tag)
{
	struct dr_match_misc2 *misc2_mask = &value->misc2;

	if (sb->inner)
		DR_STE_SET_MPLS_TAG(mpls, misc2_mask, inner, tag);
	else
		DR_STE_SET_MPLS_TAG(mpls, misc2_mask, outer, tag);

	return 0;
}

static void dr_ste_v0_build_mpls_init(struct dr_ste_build *sb,
				      struct dr_match_param *mask)
{
	dr_ste_v0_build_mpls_bit_mask(mask, sb->inner, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_LU_TYPE(MPLS_FIRST, sb->rx, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_mpls_tag;
}

static void dr_ste_v0_build_tnl_gre_bit_mask(struct dr_match_param *value,
					     uint8_t *bit_mask)
{
	struct dr_match_misc *misc_mask = &value->misc;

	DR_STE_SET_MASK_V(gre, bit_mask, gre_protocol, misc_mask, gre_protocol);
	DR_STE_SET_MASK_V(gre, bit_mask, gre_k_present, misc_mask, gre_k_present);
	DR_STE_SET_MASK_V(gre, bit_mask, gre_key_h, misc_mask, gre_key_h);
	DR_STE_SET_MASK_V(gre, bit_mask, gre_key_l, misc_mask, gre_key_l);

	DR_STE_SET_MASK_V(gre, bit_mask, gre_c_present, misc_mask, gre_c_present);
	DR_STE_SET_MASK_V(gre, bit_mask, gre_s_present, misc_mask, gre_s_present);
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
	dr_ste_v0_build_tnl_gre_bit_mask(mask, sb->bit_mask);

	sb->lu_type = DR_STE_LU_TYPE_GRE;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_tnl_gre_tag;
}

static void dr_ste_v0_build_tnl_mpls_bit_mask(struct dr_match_param *value,
					      uint8_t *bit_mask)
{
	struct dr_match_misc2 *misc2_mask = &value->misc2;

	if (DR_STE_IS_OUTER_MPLS_OVER_GRE_SET(misc2_mask)) {
		DR_STE_SET_MASK_V(flex_parser_0, bit_mask, parser_3_label,
				  misc2_mask, outer_first_mpls_over_gre_label);

		DR_STE_SET_MASK_V(flex_parser_0, bit_mask, parser_3_exp,
				  misc2_mask, outer_first_mpls_over_gre_exp);

		DR_STE_SET_MASK_V(flex_parser_0, bit_mask, parser_3_s_bos,
				  misc2_mask, outer_first_mpls_over_gre_s_bos);

		DR_STE_SET_MASK_V(flex_parser_0, bit_mask, parser_3_ttl,
				  misc2_mask, outer_first_mpls_over_gre_ttl);
	} else {
		DR_STE_SET_MASK_V(flex_parser_0, bit_mask, parser_3_label,
				  misc2_mask, outer_first_mpls_over_udp_label);

		DR_STE_SET_MASK_V(flex_parser_0, bit_mask, parser_3_exp,
				  misc2_mask, outer_first_mpls_over_udp_exp);

		DR_STE_SET_MASK_V(flex_parser_0, bit_mask, parser_3_s_bos,
				  misc2_mask, outer_first_mpls_over_udp_s_bos);

		DR_STE_SET_MASK_V(flex_parser_0, bit_mask, parser_3_ttl,
				  misc2_mask, outer_first_mpls_over_udp_ttl);
	}
}

static int dr_ste_v0_build_tnl_mpls_tag(struct dr_match_param *value,
					struct dr_ste_build *sb,
					uint8_t *tag)
{
	struct dr_match_misc2 *misc2_mask = &value->misc2;

	if (DR_STE_IS_OUTER_MPLS_OVER_GRE_SET(misc2_mask)) {
		DR_STE_SET_TAG(flex_parser_0, tag, parser_3_label,
			       misc2_mask, outer_first_mpls_over_gre_label);

		DR_STE_SET_TAG(flex_parser_0, tag, parser_3_exp,
			       misc2_mask, outer_first_mpls_over_gre_exp);

		DR_STE_SET_TAG(flex_parser_0, tag, parser_3_s_bos,
			       misc2_mask, outer_first_mpls_over_gre_s_bos);

		DR_STE_SET_TAG(flex_parser_0, tag, parser_3_ttl,
			       misc2_mask, outer_first_mpls_over_gre_ttl);
	} else {
		DR_STE_SET_TAG(flex_parser_0, tag, parser_3_label,
			       misc2_mask, outer_first_mpls_over_udp_label);

		DR_STE_SET_TAG(flex_parser_0, tag, parser_3_exp,
			       misc2_mask, outer_first_mpls_over_udp_exp);

		DR_STE_SET_TAG(flex_parser_0, tag, parser_3_s_bos,
			       misc2_mask, outer_first_mpls_over_udp_s_bos);

		DR_STE_SET_TAG(flex_parser_0, tag, parser_3_ttl,
			       misc2_mask, outer_first_mpls_over_udp_ttl);
	}

	return 0;
}

static void dr_ste_v0_build_tnl_mpls_init(struct dr_ste_build *sb,
					  struct dr_match_param *mask)
{
	dr_ste_v0_build_tnl_mpls_bit_mask(mask, sb->bit_mask);

	sb->lu_type = DR_STE_LU_TYPE_FLEX_PARSER_0;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_tnl_mpls_tag;
}

#define ICMP_TYPE_OFFSET_FIRST_DW		24
#define ICMP_CODE_OFFSET_FIRST_DW		16
#define ICMP_HEADER_DATA_OFFSET_SECOND_DW	0

static int dr_ste_v0_build_icmp_bit_mask(struct dr_match_param *mask,
					       struct dr_devx_caps *caps,
					       uint8_t *bit_mask)
{
	struct dr_match_misc3 *misc3_mask = &mask->misc3;
	bool is_ipv4_mask = DR_MASK_IS_ICMPV4_SET(misc3_mask);
	uint32_t icmp_header_data_mask;
	uint32_t icmp_type_mask;
	uint32_t icmp_code_mask;
	int dw0_location;
	int dw1_location;

	if (is_ipv4_mask) {
		icmp_header_data_mask	= misc3_mask->icmpv4_header_data;
		icmp_type_mask		= misc3_mask->icmpv4_type;
		icmp_code_mask		= misc3_mask->icmpv4_code;
		dw0_location		= caps->flex_parser_id_icmp_dw0;
		dw1_location		= caps->flex_parser_id_icmp_dw1;
	} else {
		icmp_header_data_mask	= misc3_mask->icmpv6_header_data;
		icmp_type_mask		= misc3_mask->icmpv6_type;
		icmp_code_mask		= misc3_mask->icmpv6_code;
		dw0_location		= caps->flex_parser_id_icmpv6_dw0;
		dw1_location		= caps->flex_parser_id_icmpv6_dw1;
	}

	switch (dw0_location) {
	case 4:
		if (icmp_type_mask) {
			DR_STE_SET(flex_parser_1, bit_mask, flex_parser_4,
				   (icmp_type_mask << ICMP_TYPE_OFFSET_FIRST_DW));
			if (is_ipv4_mask)
				misc3_mask->icmpv4_type = 0;
			else
				misc3_mask->icmpv6_type = 0;
		}
		if (icmp_code_mask) {
			uint32_t cur_val = DR_STE_GET(flex_parser_1, bit_mask,
						      flex_parser_4);
			DR_STE_SET(flex_parser_1, bit_mask, flex_parser_4,
				   cur_val | (icmp_code_mask << ICMP_CODE_OFFSET_FIRST_DW));
			if (is_ipv4_mask)
				misc3_mask->icmpv4_code = 0;
			else
				misc3_mask->icmpv6_code = 0;
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
				misc3_mask->icmpv4_header_data = 0;
			else
				misc3_mask->icmpv6_header_data = 0;
		}
		break;
	default:
		errno = ENOTSUP;
		return errno;
	}

	return 0;
}

static int dr_ste_v0_build_icmp_tag(struct dr_match_param *value,
				    struct dr_ste_build *sb,
				    uint8_t *tag)
{
	struct dr_match_misc3 *misc3 = &value->misc3;
	bool is_ipv4 = DR_MASK_IS_ICMPV4_SET(misc3);
	uint32_t icmp_header_data;
	uint32_t icmp_type;
	uint32_t icmp_code;
	int dw0_location;
	int dw1_location;

	if (is_ipv4) {
		icmp_header_data	= misc3->icmpv4_header_data;
		icmp_type		= misc3->icmpv4_type;
		icmp_code		= misc3->icmpv4_code;
		dw0_location		= sb->caps->flex_parser_id_icmp_dw0;
		dw1_location		= sb->caps->flex_parser_id_icmp_dw1;
	} else {
		icmp_header_data	= misc3->icmpv6_header_data;
		icmp_type		= misc3->icmpv6_type;
		icmp_code		= misc3->icmpv6_code;
		dw0_location		= sb->caps->flex_parser_id_icmpv6_dw0;
		dw1_location		= sb->caps->flex_parser_id_icmpv6_dw1;
	}

	switch (dw0_location) {
	case 4:
		if (icmp_type) {
			DR_STE_SET(flex_parser_1, tag, flex_parser_4,
				   (icmp_type << ICMP_TYPE_OFFSET_FIRST_DW));
			if (is_ipv4)
				misc3->icmpv4_type = 0;
			else
				misc3->icmpv6_type = 0;
		}

		if (icmp_code) {
			uint32_t cur_val = DR_STE_GET(flex_parser_1, tag,
						      flex_parser_4);
			DR_STE_SET(flex_parser_1, tag, flex_parser_4,
				   cur_val | (icmp_code << ICMP_CODE_OFFSET_FIRST_DW));
			if (is_ipv4)
				misc3->icmpv4_code = 0;
			else
				misc3->icmpv6_code = 0;
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
				misc3->icmpv4_header_data = 0;
			else
				misc3->icmpv6_header_data = 0;
		}
		break;
	default:
		errno = ENOTSUP;
		return errno;
	}

	return 0;
}

static int dr_ste_v0_build_icmp_init(struct dr_ste_build *sb,
				     struct dr_match_param *mask)
{
	int ret;

	ret = dr_ste_v0_build_icmp_bit_mask(mask, sb->caps, sb->bit_mask);
	if (ret)
		return ret;

	sb->lu_type = DR_STE_LU_TYPE_FLEX_PARSER_1;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_icmp_tag;

	return 0;
}

static void dr_ste_v0_build_general_purpose_bit_mask(struct dr_match_param *value,
						     uint8_t *bit_mask)
{
	struct dr_match_misc2 *misc2_mask = &value->misc2;

	DR_STE_SET_MASK_V(general_purpose, bit_mask,
			  general_purpose_lookup_field, misc2_mask,
			  metadata_reg_a);
}

static int dr_ste_v0_build_general_purpose_tag(struct dr_match_param *value,
					       struct dr_ste_build *sb,
					       uint8_t *tag)
{
	struct dr_match_misc2 *misc2_mask = &value->misc2;

	DR_STE_SET_TAG(general_purpose, tag, general_purpose_lookup_field,
		       misc2_mask, metadata_reg_a);

	return 0;
}

static void dr_ste_v0_build_general_purpose_init(struct dr_ste_build *sb,
						 struct dr_match_param *mask)
{
	dr_ste_v0_build_general_purpose_bit_mask(mask, sb->bit_mask);

	sb->lu_type = DR_STE_LU_TYPE_GENERAL_PURPOSE;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_general_purpose_tag;
}

static void dr_ste_v0_build_eth_l4_misc_bit_mask(struct dr_match_param *value,
						 bool inner, uint8_t *bit_mask)
{
	struct dr_match_misc3 *misc3_mask = &value->misc3;

	if (inner) {
		DR_STE_SET_MASK_V(eth_l4_misc, bit_mask, seq_num, misc3_mask,
				  inner_tcp_seq_num);
		DR_STE_SET_MASK_V(eth_l4_misc, bit_mask, ack_num, misc3_mask,
				  inner_tcp_ack_num);
	} else {
		DR_STE_SET_MASK_V(eth_l4_misc, bit_mask, seq_num, misc3_mask,
				  outer_tcp_seq_num);
		DR_STE_SET_MASK_V(eth_l4_misc, bit_mask, ack_num, misc3_mask,
				  outer_tcp_ack_num);
	}
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
	dr_ste_v0_build_eth_l4_misc_bit_mask(mask, sb->inner, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_LU_TYPE(ETHL4_MISC, sb->rx, sb->inner);
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_eth_l4_misc_tag;
}

static void
dr_ste_v0_build_flex_parser_tnl_vxlan_gpe_bit_mask(struct dr_match_param *value,
						   uint8_t *bit_mask)
{
	struct dr_match_misc3 *misc3_mask = &value->misc3;

	DR_STE_SET_MASK_V(flex_parser_tnl_vxlan_gpe, bit_mask,
			  outer_vxlan_gpe_flags,
			  misc3_mask, outer_vxlan_gpe_flags);
	DR_STE_SET_MASK_V(flex_parser_tnl_vxlan_gpe, bit_mask,
			  outer_vxlan_gpe_next_protocol,
			  misc3_mask, outer_vxlan_gpe_next_protocol);
	DR_STE_SET_MASK_V(flex_parser_tnl_vxlan_gpe, bit_mask,
			  outer_vxlan_gpe_vni,
			  misc3_mask, outer_vxlan_gpe_vni);
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
	dr_ste_v0_build_flex_parser_tnl_vxlan_gpe_bit_mask(mask, sb->bit_mask);

	sb->lu_type = DR_STE_LU_TYPE_FLEX_PARSER_TNL_HEADER;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_flex_parser_tnl_vxlan_gpe_tag;
}

static void
dr_ste_v0_build_flex_parser_tnl_geneve_bit_mask(struct dr_match_param *value,
						uint8_t *bit_mask)
{
	struct dr_match_misc *misc_mask = &value->misc;

	DR_STE_SET_MASK_V(flex_parser_tnl_geneve, bit_mask,
			  geneve_protocol_type,
			  misc_mask, geneve_protocol_type);
	DR_STE_SET_MASK_V(flex_parser_tnl_geneve, bit_mask,
			  geneve_oam,
			  misc_mask, geneve_oam);
	DR_STE_SET_MASK_V(flex_parser_tnl_geneve, bit_mask,
			  geneve_opt_len,
			  misc_mask, geneve_opt_len);
	DR_STE_SET_MASK_V(flex_parser_tnl_geneve, bit_mask,
			  geneve_vni,
			  misc_mask, geneve_vni);
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
	dr_ste_v0_build_flex_parser_tnl_geneve_bit_mask(mask, sb->bit_mask);

	sb->lu_type = DR_STE_LU_TYPE_FLEX_PARSER_TNL_HEADER;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_flex_parser_tnl_geneve_tag;
}

static void
dr_ste_v0_build_flex_parser_tnl_gtpu_bit_mask(struct dr_match_param *value,
					      uint8_t *bit_mask)
{
	struct dr_match_misc3 *misc3_mask = &value->misc3;

	DR_STE_SET_MASK_V(flex_parser_tnl_gtpu, bit_mask,
			  gtpu_flags, misc3_mask,
			  gtpu_flags);
	DR_STE_SET_MASK_V(flex_parser_tnl_gtpu, bit_mask,
			  gtpu_msg_type, misc3_mask,
			  gtpu_msg_type);
	DR_STE_SET_MASK_V(flex_parser_tnl_gtpu, bit_mask,
			  gtpu_teid, misc3_mask,
			  gtpu_teid);
}

static int dr_ste_v0_build_flex_parser_tnl_gtpu_tag(struct dr_match_param *value,
						    struct dr_ste_build *sb,
						     uint8_t *tag)
{
	struct dr_match_misc3 *misc3 = &value->misc3;

	DR_STE_SET_TAG(flex_parser_tnl_gtpu, tag,
		       gtpu_flags, misc3,
		       gtpu_flags);
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
	dr_ste_v0_build_flex_parser_tnl_gtpu_bit_mask(mask, sb->bit_mask);

	sb->lu_type = DR_STE_LU_TYPE_FLEX_PARSER_TNL_HEADER;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_flex_parser_tnl_gtpu_tag;
}

static void dr_ste_v0_build_register_0_bit_mask(struct dr_match_param *value,
						uint8_t *bit_mask)
{
	struct dr_match_misc2 *misc2_mask = &value->misc2;

	DR_STE_SET_MASK_V(register_0, bit_mask, register_0_h,
			  misc2_mask, metadata_reg_c_0);
	DR_STE_SET_MASK_V(register_0, bit_mask, register_0_l,
			  misc2_mask, metadata_reg_c_1);
	DR_STE_SET_MASK_V(register_0, bit_mask, register_1_h,
			  misc2_mask, metadata_reg_c_2);
	DR_STE_SET_MASK_V(register_0, bit_mask, register_1_l,
			  misc2_mask, metadata_reg_c_3);
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
	dr_ste_v0_build_register_0_bit_mask(mask, sb->bit_mask);

	sb->lu_type = DR_STE_LU_TYPE_STEERING_REGISTERS_0;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_register_0_tag;
}

static void dr_ste_v0_build_register_1_bit_mask(struct dr_match_param *value,
						uint8_t *bit_mask)
{
	struct dr_match_misc2 *misc2_mask = &value->misc2;

	DR_STE_SET_MASK_V(register_1, bit_mask, register_2_h,
			  misc2_mask, metadata_reg_c_4);
	DR_STE_SET_MASK_V(register_1, bit_mask, register_2_l,
			  misc2_mask, metadata_reg_c_5);
	DR_STE_SET_MASK_V(register_1, bit_mask, register_3_h,
			  misc2_mask, metadata_reg_c_6);
	DR_STE_SET_MASK_V(register_1, bit_mask, register_3_l,
			  misc2_mask, metadata_reg_c_7);
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
	dr_ste_v0_build_register_1_bit_mask(mask, sb->bit_mask);

	sb->lu_type = DR_STE_LU_TYPE_STEERING_REGISTERS_1;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_register_1_tag;
}

static void dr_ste_v0_build_src_gvmi_qpn_bit_mask(struct dr_match_param *value,
						  uint8_t *bit_mask)
{
	struct dr_match_misc *misc_mask = &value->misc;

	DR_STE_SET_MASK(src_gvmi_qp, bit_mask, source_gvmi, misc_mask, source_port);
	DR_STE_SET_MASK(src_gvmi_qp, bit_mask, source_qp, misc_mask, source_sqn);
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
		vport_cap = dr_get_vport_cap(sb->caps, misc->source_port);
		if (!vport_cap)
			return errno;

		if (vport_cap->gvmi)
			DR_STE_SET(src_gvmi_qp, tag, source_gvmi, vport_cap->gvmi);

		misc->source_port = 0;
	}

	return 0;
}

static void dr_ste_v0_build_src_gvmi_qpn_init(struct dr_ste_build *sb,
					      struct dr_match_param *mask)
{
	dr_ste_v0_build_src_gvmi_qpn_bit_mask(mask, sb->bit_mask);

	sb->lu_type = DR_STE_LU_TYPE_SRC_GVMI_AND_QP;
	sb->byte_mask = dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v0_build_src_gvmi_qpn_tag;
}

static struct dr_ste_ctx ste_ctx_v0 = {
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
	.build_tnl_mpls_init		= &dr_ste_v0_build_tnl_mpls_init,
	.build_icmp_init		= &dr_ste_v0_build_icmp_init,
	.build_general_purpose_init	= &dr_ste_v0_build_general_purpose_init,
	.build_eth_l4_misc_init		= &dr_ste_v0_build_eth_l4_misc_init,
	.build_tnl_vxlan_gpe_init	= &dr_ste_v0_build_flex_parser_tnl_vxlan_gpe_init,
	.build_tnl_geneve_init		= &dr_ste_v0_build_flex_parser_tnl_geneve_init,
	.build_tnl_gtpu_init		= &dr_ste_v0_build_flex_parser_tnl_gtpu_init,
	.build_register_0_init		= &dr_ste_v0_build_register_0_init,
	.build_register_1_init		= &dr_ste_v0_build_register_1_init,
	.build_src_gvmi_qpn_init	= &dr_ste_v0_build_src_gvmi_qpn_init,
};

struct dr_ste_ctx *dr_ste_get_ctx_v0(void)
{
	return &ste_ctx_v0;
}
