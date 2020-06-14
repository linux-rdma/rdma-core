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
	DR_STE_SET_VAL(lookup_type, tag, t_fname, spec, s_fname, (spec)->s_fname)

/* Set to STE -1 to bit_mask->bm_fname and set spec->s_fname as used */
#define DR_STE_SET_MASK(lookup_type, bit_mask, bm_fname, spec, s_fname) \
	DR_STE_SET_VAL(lookup_type, bit_mask, bm_fname, spec, s_fname, -1)

/* Set to STE spec->s_fname to bit_mask->bm_fname and set spec->s_fname as used */
#define DR_STE_SET_MASK_V(lookup_type, bit_mask, bm_fname, spec, s_fname) \
	DR_STE_SET_VAL(lookup_type, bit_mask, bm_fname, spec, s_fname, (spec)->s_fname)


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

uint16_t dr_ste_conv_bit_to_byte_mask(uint8_t *bit_mask);

typedef void (*dr_ste_builder_void_init)(struct dr_ste_build *sb,
					 struct dr_match_param *mask);

typedef int (*dr_ste_builder_int_init)(struct dr_ste_build *sb,
				       struct dr_match_param *mask);
struct dr_ste_ctx {
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
	dr_ste_builder_void_init build_tnl_mpls_init;
	dr_ste_builder_int_init  build_icmp_init;
	dr_ste_builder_void_init build_general_purpose_init;
	dr_ste_builder_void_init build_eth_l4_misc_init;
	dr_ste_builder_void_init build_tnl_vxlan_gpe_init;
	dr_ste_builder_void_init build_tnl_geneve_init;
	dr_ste_builder_void_init build_tnl_gtpu_init;
	dr_ste_builder_void_init build_register_0_init;
	dr_ste_builder_void_init build_register_1_init;
	dr_ste_builder_void_init build_src_gvmi_qpn_init;
};

struct dr_ste_ctx *dr_ste_get_ctx_v0(void);

#endif
