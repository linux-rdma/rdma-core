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

#ifndef	_MLX5_DV_DR_
#define	_MLX5_DV_DR_

#include <ccan/list.h>
#include <ccan/minmax.h>
#include <stdatomic.h>
#include "mlx5dv.h"
#include "mlx5_ifc.h"
#include "mlx5.h"

#define DR_RULE_MAX_STES	17
#define DR_ACTION_MAX_STES	3
#define WIRE_PORT		0xFFFF
#define DR_STE_SVLAN		0x1
#define DR_STE_CVLAN		0x2

#define dr_dbg(dmn, arg...) dr_dbg_ctx((dmn)->ctx, ##arg)

#define dr_dbg_ctx(ctx, arg...)					\
	mlx5_dbg(to_mctx(ctx)->dbg_fp, MLX5_DBG_DR, ##arg);

enum dr_icm_chunk_size {
	DR_CHUNK_SIZE_1,
	DR_CHUNK_SIZE_MIN = DR_CHUNK_SIZE_1, /* keep updated when changing */
	DR_CHUNK_SIZE_2,
	DR_CHUNK_SIZE_4,
	DR_CHUNK_SIZE_8,
	DR_CHUNK_SIZE_16,
	DR_CHUNK_SIZE_32,
	DR_CHUNK_SIZE_64,
	DR_CHUNK_SIZE_128,
	DR_CHUNK_SIZE_256,
	DR_CHUNK_SIZE_512,
	DR_CHUNK_SIZE_1K,
	DR_CHUNK_SIZE_2K,
	DR_CHUNK_SIZE_4K,
	DR_CHUNK_SIZE_8K,
	DR_CHUNK_SIZE_16K,
	DR_CHUNK_SIZE_32K,
	DR_CHUNK_SIZE_64K,
	DR_CHUNK_SIZE_128K,
	DR_CHUNK_SIZE_256K,
	DR_CHUNK_SIZE_512K,
	DR_CHUNK_SIZE_1024K,
	DR_CHUNK_SIZE_2048K,
	DR_CHUNK_SIZE_MAX,
};

enum dr_icm_type {
	DR_ICM_TYPE_STE,
	DR_ICM_TYPE_MODIFY_ACTION,
};

static inline enum dr_icm_chunk_size
dr_icm_next_higher_chunk(enum dr_icm_chunk_size chunk)
{
	chunk += 2;
	if (chunk < DR_CHUNK_SIZE_MAX)
		return chunk;

	return DR_CHUNK_SIZE_MAX;
}

enum dr_ste_lu_type {
	DR_STE_LU_TYPE_NOP			= 0x00,
	DR_STE_LU_TYPE_SRC_GVMI_AND_QP		= 0x05,
	DR_STE_LU_TYPE_ETHL2_TUNNELING_I	= 0x0a,
	DR_STE_LU_TYPE_ETHL2_DST_O		= 0x06,
	DR_STE_LU_TYPE_ETHL2_DST_I		= 0x07,
	DR_STE_LU_TYPE_ETHL2_DST_D		= 0x1b,
	DR_STE_LU_TYPE_ETHL2_SRC_O		= 0x08,
	DR_STE_LU_TYPE_ETHL2_SRC_I		= 0x09,
	DR_STE_LU_TYPE_ETHL2_SRC_D		= 0x1c,
	DR_STE_LU_TYPE_ETHL2_SRC_DST_O		= 0x36,
	DR_STE_LU_TYPE_ETHL2_SRC_DST_I		= 0x37,
	DR_STE_LU_TYPE_ETHL2_SRC_DST_D		= 0x38,
	DR_STE_LU_TYPE_ETHL3_IPV6_DST_O		= 0x0d,
	DR_STE_LU_TYPE_ETHL3_IPV6_DST_I		= 0x0e,
	DR_STE_LU_TYPE_ETHL3_IPV6_DST_D		= 0x1e,
	DR_STE_LU_TYPE_ETHL3_IPV6_SRC_O		= 0x0f,
	DR_STE_LU_TYPE_ETHL3_IPV6_SRC_I		= 0x10,
	DR_STE_LU_TYPE_ETHL3_IPV6_SRC_D		= 0x1f,
	DR_STE_LU_TYPE_ETHL3_IPV4_5_TUPLE_O	= 0x11,
	DR_STE_LU_TYPE_ETHL3_IPV4_5_TUPLE_I	= 0x12,
	DR_STE_LU_TYPE_ETHL3_IPV4_5_TUPLE_D	= 0x20,
	DR_STE_LU_TYPE_ETHL3_IPV4_MISC_O	= 0x29,
	DR_STE_LU_TYPE_ETHL3_IPV4_MISC_I	= 0x2a,
	DR_STE_LU_TYPE_ETHL3_IPV4_MISC_D	= 0x2b,
	DR_STE_LU_TYPE_ETHL4_O			= 0x13,
	DR_STE_LU_TYPE_ETHL4_I			= 0x14,
	DR_STE_LU_TYPE_ETHL4_D			= 0x21,
	DR_STE_LU_TYPE_ETHL4_MISC_O		= 0x2c,
	DR_STE_LU_TYPE_ETHL4_MISC_I		= 0x2d,
	DR_STE_LU_TYPE_ETHL4_MISC_D		= 0x2e,
	DR_STE_LU_TYPE_MPLS_FIRST_O		= 0x15,
	DR_STE_LU_TYPE_MPLS_FIRST_I		= 0x24,
	DR_STE_LU_TYPE_MPLS_FIRST_D		= 0x25,
	DR_STE_LU_TYPE_GRE			= 0x16,
	DR_STE_LU_TYPE_FLEX_PARSER_0		= 0x22,
	DR_STE_LU_TYPE_FLEX_PARSER_1		= 0x23,
	DR_STE_LU_TYPE_FLEX_PARSER_TNL_HEADER	= 0x19,
	DR_STE_LU_TYPE_GENERAL_PURPOSE		= 0x18,
	DR_STE_LU_TYPE_STEERING_REGISTERS_0	= 0x2f,
	DR_STE_LU_TYPE_STEERING_REGISTERS_1	= 0x30,
	DR_STE_LU_TYPE_DONT_CARE		= 0x0f,
};

enum dr_ste_entry_type {
	DR_STE_TYPE_TX		= 1,
	DR_STE_TYPE_RX		= 2,
	DR_STE_TYPE_MODIFY_PKT	= 6,
};

enum {
	DR_STE_SIZE		= 64,
	DR_STE_SIZE_CTRL	= 32,
	DR_STE_SIZE_TAG		= 16,
	DR_STE_SIZE_MASK	= 16,
};

enum {
	DR_STE_SIZE_REDUCED = DR_STE_SIZE - DR_STE_SIZE_MASK,
};

enum {
	DR_MODIFY_ACTION_SIZE	= 8,
};

enum dr_matcher_criteria {
	DR_MATCHER_CRITERIA_EMPTY	= 0,
	DR_MATCHER_CRITERIA_OUTER	= 1 << 0,
	DR_MATCHER_CRITERIA_MISC	= 1 << 1,
	DR_MATCHER_CRITERIA_INNER	= 1 << 2,
	DR_MATCHER_CRITERIA_MISC2	= 1 << 3,
	DR_MATCHER_CRITERIA_MISC3	= 1 << 4,
	DR_MATCHER_CRITERIA_MAX		= 1 << 5,
};

enum dr_action_type {
	DR_ACTION_TYP_TNL_L2_TO_L2,
	DR_ACTION_TYP_L2_TO_TNL_L2,
	DR_ACTION_TYP_TNL_L3_TO_L2,
	DR_ACTION_TYP_L2_TO_TNL_L3,
	DR_ACTION_TYP_DROP,
	DR_ACTION_TYP_QP,
	DR_ACTION_TYP_FT,
	DR_ACTION_TYP_CTR,
	DR_ACTION_TYP_TAG,
	DR_ACTION_TYP_MODIFY_HDR,
	DR_ACTION_TYP_VPORT,
	DR_ACTION_TYP_MAX,
};

struct dr_icm_pool;
struct dr_icm_chunk;
struct dr_icm_bucket;
struct dr_ste_htbl;
struct dr_match_param;
struct dr_devx_caps;
struct dr_matcher_rx_tx;

struct dr_data_seg {
	uint64_t	addr;
	uint32_t	length;
	uint32_t	lkey;
	unsigned int	send_flags;
};

struct postsend_info {
	struct dr_data_seg	write;
	struct dr_data_seg	read;
	uint64_t		remote_addr;
	uint32_t		rkey;
};

struct dr_ste {
	uint8_t			*hw_ste;
	/* refcount: indicates the num of rules that using this ste */
	atomic_int		refcount;

	/* attached to the miss_list head at each htbl entry */
	struct list_node	miss_list_node;

	/* each rule member that uses this ste attached here */
	struct list_head	rule_list;

	/* this ste is member of htbl */
	struct dr_ste_htbl	*htbl;

	struct dr_ste_htbl	*next_htbl;

	/* this ste is part of a rule, located in ste's chain */
	uint8_t			ste_chain_location;
};

struct dr_ste_htbl_ctrl {
	/* total number of valid entries belonging to this hash table. This
	 * includes the non collision and collision entries
	 */
	int	num_of_valid_entries;

	/* total number of collisions entries attached to this table */
	int	num_of_collisions;
	int	increase_threshold;
	bool	may_grow;
};

struct dr_ste_htbl {
	uint8_t			lu_type;
	uint16_t		byte_mask;
	atomic_int		refcount;
	struct dr_icm_chunk	*chunk;
	struct dr_ste		*ste_arr;
	uint8_t			*hw_ste_arr;

	struct list_head	*miss_list;

	enum dr_icm_chunk_size	chunk_size;
	struct dr_ste		*pointing_ste;

	struct dr_ste_htbl_ctrl ctrl;
};

struct dr_ste_send_info {
	struct dr_ste		*ste;
	struct list_node	send_list;
	uint16_t		size;
	uint16_t		offset;
	uint8_t			data_cont[DR_STE_SIZE];
	uint8_t			*data;
};

void dr_send_fill_and_append_ste_send_info(struct dr_ste *ste, uint16_t size,
					   uint16_t offset, uint8_t *data,
					   struct dr_ste_send_info *ste_info,
					   struct list_head *send_list,
					   bool copy_data);

struct dr_ste_build {
	bool			inner;
	bool			rx;
	struct dr_devx_caps	*caps;
	uint8_t			lu_type;
	uint16_t		byte_mask;
	uint8_t			bit_mask[DR_STE_SIZE_MASK];
	int (*ste_build_tag_func)(struct dr_match_param *spec,
				  struct dr_ste_build *sb,
				  uint8_t *hw_ste_p);
};

struct dr_ste_htbl *dr_ste_htbl_alloc(struct dr_icm_pool *pool,
				      enum dr_icm_chunk_size chunk_size,
				      uint8_t lu_type, uint16_t byte_mask);
int dr_ste_htbl_free(struct dr_ste_htbl *htbl);

static inline void dr_htbl_put(struct dr_ste_htbl *htbl)
{
	if (atomic_fetch_sub(&htbl->refcount, 1) == 1)
		dr_ste_htbl_free(htbl);
}

static inline void dr_htbl_get(struct dr_ste_htbl *htbl)
{
	atomic_fetch_add(&htbl->refcount, 1);
}

/* STE utils */
uint32_t dr_ste_calc_hash_index(uint8_t *hw_ste_p, struct dr_ste_htbl *htbl);
void dr_ste_init(uint8_t *hw_ste_p, uint8_t lu_type, uint8_t entry_type, uint16_t gvmi);
void dr_ste_always_hit_htbl(struct dr_ste *ste, struct dr_ste_htbl *next_htbl);
void dr_ste_set_miss_addr(uint8_t *hw_ste, uint64_t miss_addr);
uint64_t dr_ste_get_miss_addr(uint8_t *hw_ste);
void dr_ste_set_hit_addr(uint8_t *hw_ste, uint64_t icm_addr, uint32_t ht_size);
void dr_ste_always_miss_addr(struct dr_ste *ste, uint64_t miss_addr);
void dr_ste_set_bit_mask(uint8_t *hw_ste_p, uint8_t *bit_mask);
bool dr_ste_not_used_ste(struct dr_ste *ste);
bool dr_ste_is_last_in_rule(struct dr_matcher_rx_tx *nic_matcher,
			    uint8_t ste_location);
void dr_ste_rx_set_flow_tag(uint8_t *hw_ste_p, uint32_t flow_tag);
void dr_ste_set_counter_id(uint8_t *hw_ste_p, uint32_t ctr_id);
void dr_ste_set_tx_encap(void *hw_ste_p, uint32_t reformat_id, int size, bool encap_l3);
void dr_ste_set_rx_decap(uint8_t *hw_ste_p);
void dr_ste_set_rx_decap_l3(uint8_t *hw_ste_p, bool vlan);
void dr_ste_set_entry_type(uint8_t *hw_ste_p, uint8_t entry_type);
uint8_t dr_ste_get_entry_type(uint8_t *hw_ste_p);
void dr_ste_set_rewrite_actions(uint8_t *hw_ste_p, uint16_t num_of_actions,
				uint32_t re_write_index);
uint64_t dr_ste_get_icm_addr(struct dr_ste *ste);
uint64_t dr_ste_get_mr_addr(struct dr_ste *ste);
struct list_head *dr_ste_get_miss_list(struct dr_ste *ste);

void dr_ste_free(struct dr_ste *ste,
		 struct mlx5dv_dr_matcher *matcher,
		 struct dr_matcher_rx_tx *nic_matcher);
static inline void dr_ste_put(struct dr_ste *ste,
			      struct mlx5dv_dr_matcher *matcher,
			      struct dr_matcher_rx_tx *nic_matcher)
{
	if (atomic_fetch_sub(&ste->refcount, 1) == 1)
		dr_ste_free(ste, matcher, nic_matcher);
}

/* initial as 0, increased only when ste appears in a new rule */
static inline void dr_ste_get(struct dr_ste *ste)
{
	atomic_fetch_add(&ste->refcount, 1);
}

void dr_ste_set_hit_addr_by_next_htbl(uint8_t *hw_ste,
				      struct dr_ste_htbl *next_htbl);
bool dr_ste_equal_tag(void *src, void *dst);
int dr_ste_create_next_htbl(struct mlx5dv_dr_matcher *matcher,
			    struct dr_matcher_rx_tx *nic_matcher,
			    struct dr_ste *ste,
			    uint8_t *cur_hw_ste,
			    enum dr_icm_chunk_size log_table_size);

/* STE build functions */
int dr_ste_build_pre_check(struct mlx5dv_dr_domain *dmn,
			   uint8_t match_criteria,
			   struct dr_match_param *mask,
			   struct dr_match_param *value);
int dr_ste_build_ste_arr(struct mlx5dv_dr_matcher *matcher,
			 struct dr_matcher_rx_tx *nic_matcher,
			 struct dr_match_param *value,
			 uint8_t *ste_arr);
int dr_ste_build_eth_l2_src_des(struct dr_ste_build *builder,
				struct dr_match_param *mask,
				bool inner, bool rx);
void dr_ste_build_eth_l3_ipv4_5_tuple(struct dr_ste_build *sb,
				      struct dr_match_param *mask,
				      bool inner, bool rx);
void dr_ste_build_eth_l3_ipv4_misc(struct dr_ste_build *sb,
				   struct dr_match_param *mask,
				   bool inner, bool rx);
void dr_ste_build_eth_l3_ipv6_dst(struct dr_ste_build *sb,
				  struct dr_match_param *mask,
				  bool inner, bool rx);
void dr_ste_build_eth_l3_ipv6_src(struct dr_ste_build *sb,
				  struct dr_match_param *mask,
				  bool inner, bool rx);
void dr_ste_build_eth_l2_src(struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx);
void dr_ste_build_eth_l2_dst(struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx);
void dr_ste_build_eth_l2_tnl(struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx);
void dr_ste_build_ipv6_l3_l4(struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx);
void dr_ste_build_eth_l4_misc(struct dr_ste_build *sb,
			      struct dr_match_param *mask,
			      bool inner, bool rx);
void dr_ste_build_gre(struct dr_ste_build *sb,
		      struct dr_match_param *mask,
		      bool inner, bool rx);
void dr_ste_build_mpls(struct dr_ste_build *sb,
		       struct dr_match_param *mask,
		       bool inner, bool rx);
void dr_ste_build_flex_parser_0(struct dr_ste_build *sb,
				struct dr_match_param *mask,
				bool inner, bool rx);
int dr_ste_build_flex_parser_1(struct dr_ste_build *sb,
			       struct dr_match_param *mask,
			       struct dr_devx_caps *caps,
			       bool inner, bool rx);
void dr_ste_build_flex_parser_tnl(struct dr_ste_build *sb,
				  struct dr_match_param *mask,
				  bool inner, bool rx);
void dr_ste_build_general_purpose(struct dr_ste_build *sb,
				  struct dr_match_param *mask,
				  bool inner, bool rx);
void dr_ste_build_register_0(struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx);
void dr_ste_build_register_1(struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx);
int dr_ste_build_src_gvmi_qpn(struct dr_ste_build *sb,
			      struct dr_match_param *mask,
			      struct dr_devx_caps *caps,
			      bool inner, bool rx);
void dr_ste_build_empty_always_hit(struct dr_ste_build *sb, bool rx);

/* Actions utils */
int dr_actions_build_ste_arr(struct mlx5dv_dr_matcher *matcher,
			     struct dr_matcher_rx_tx *nic_matcher,
			     struct mlx5dv_dr_action *actions[],
			     uint32_t num_actions,
			     uint8_t *ste_arr,
			     uint32_t *new_hw_ste_arr_sz);
int dr_actions_build_attr(struct mlx5dv_dr_matcher *matcher,
			  struct mlx5dv_dr_action *actions[],
			  size_t num_actions,
			  struct mlx5dv_flow_action_attr *attr);

struct dr_match_spec {
	uint32_t smac_47_16;	/* Source MAC address of incoming packet */
	uint32_t ethertype:16;	/* Incoming packet Ethertype - this is the Ethertype following the last ;VLAN tag of the packet */
	uint32_t smac_15_0:16;	/* Source MAC address of incoming packet */
	uint32_t dmac_47_16;	/* Destination MAC address of incoming packet */
	uint32_t first_vid:12;	/* VLAN ID of first VLAN tag in the incoming packet. Valid only ;when cvlan_tag==1 or svlan_tag==1 */
	uint32_t first_cfi:1;	/* CFI bit of first VLAN tag in the incoming packet. Valid only when ;cvlan_tag==1 or svlan_tag==1 */
	uint32_t first_prio:3;	/* Priority of first VLAN tag in the incoming packet. Valid only when ;cvlan_tag==1 or svlan_tag==1 */
	uint32_t dmac_15_0:16;	/* Destination MAC address of incoming packet */
	uint32_t tcp_flags:9;	/* TCP flags. ;Bit 0: FIN;Bit 1: SYN;Bit 2: RST;Bit 3: PSH;Bit 4: ACK;Bit 5: URG;Bit 6: ECE;Bit 7: CWR;Bit 8: NS */
	uint32_t ip_version:4;	/* IP version */
	uint32_t frag:1;	/* Packet is an IP fragment */
	uint32_t svlan_tag:1;	/* The first vlan in the packet is s-vlan (0x8a88). cvlan_tag and ;svlan_tag cannot be set together */
	uint32_t cvlan_tag:1;	/* The first vlan in the packet is c-vlan (0x8100). cvlan_tag and ;svlan_tag cannot be set together */
	uint32_t ip_ecn:2;	/* Explicit Congestion Notification derived from Traffic Class/TOS ;field of IPv6/v4 */
	uint32_t ip_dscp:6;	/* Differentiated Services Code Point derived from Traffic Class/;TOS field of IPv6/v4 */
	uint32_t ip_protocol:8;	/* IP protocol */
	uint32_t tcp_dport:16;	/* TCP destination port. ;tcp and udp sport/dport are mutually exclusive */
	uint32_t tcp_sport:16;	/* TCP source port.;tcp and udp sport/dport are mutually exclusive */
	uint32_t ip_ttl_hoplimit:8;
	uint32_t reserved:24;
	uint32_t udp_dport:16;	/* UDP destination port.;tcp and udp sport/dport are mutually exclusive */
	uint32_t udp_sport:16;	/* UDP source port.;tcp and udp sport/dport are mutually exclusive */
	uint32_t src_ip_127_96;	/* IPv6 source address of incoming packets ;For IPv4 address use bits 31:0 (rest of the bits are reserved);This field should be qualified by an appropriate ;ethertype */
	uint32_t src_ip_95_64;	/* IPv6 source address of incoming packets ;For IPv4 address use bits 31:0 (rest of the bits are reserved);This field should be qualified by an appropriate ;ethertype */
	uint32_t src_ip_63_32;	/* IPv6 source address of incoming packets ;For IPv4 address use bits 31:0 (rest of the bits are reserved);This field should be qualified by an appropriate ;ethertype */
	uint32_t src_ip_31_0;	/* IPv6 source address of incoming packets ;For IPv4 address use bits 31:0 (rest of the bits are reserved);This field should be qualified by an appropriate ;ethertype */
	uint32_t dst_ip_127_96;	/* IPv6 destination address of incoming packets ;For IPv4 address use bits 31:0 (rest of the bits are reserved);This field should be qualified by an appropriate ;ethertype */
	uint32_t dst_ip_95_64;	/* IPv6 destination address of incoming packets ;For IPv4 address use bits 31:0 (rest of the bits are reserved);This field should be qualified by an appropriate ;ethertype */
	uint32_t dst_ip_63_32;	/* IPv6 destination address of incoming packets ;For IPv4 address use bits 31:0 (rest of the bits are reserved);This field should be qualified by an appropriate ;ethertype */
	uint32_t dst_ip_31_0;	/* IPv6 destination address of incoming packets ;For IPv4 address use bits 31:0 (rest of the bits are reserved);This field should be qualified by an appropriate ;ethertype */
};

struct dr_match_misc {
	uint32_t source_sqn:24;			/* Source SQN */
	uint32_t source_vhca_port:4;
	uint32_t gre_s_present:1;		/* used with GRE, sequence number exist when gre_s_present == 1 */
	uint32_t gre_k_present:1;		/* used with GRE, key exist when gre_k_present == 1 */
	uint32_t reserved_auto1:1;
	uint32_t gre_c_present:1;		/* used with GRE, checksum exist when gre_c_present == 1 */
	uint32_t source_port:16;		/* Source port.;0xffff determines wire port */
	uint32_t reserved_auto2:16;
	uint32_t inner_second_vid:12;		/* VLAN ID of first VLAN tag the inner header of the incoming packet. ;Valid only when inner_second_cvlan_tag ==1 or inner_sec;ond_svlan_tag ==1 */
	uint32_t inner_second_cfi:1;		/* CFI bit of first VLAN tag in the inner header of the incoming packet. ;Valid only when inner_second_cvlan_tag ==1 or inner_sec;ond_svlan_tag ==1 */
	uint32_t inner_second_prio:3;		/* Priority of second VLAN tag in the inner header of the incoming ;packet. Valid only when inner_second_cvlan_tag ==1 or inner_sec;ond_svlan_tag ==1 */
	uint32_t outer_second_vid:12;		/* VLAN ID of first VLAN tag the outer header of the incoming packet. ;Valid only when outer_second_cvlan_tag ==1 or outer_sec;ond_svlan_tag ==1 */
	uint32_t outer_second_cfi:1;		/* CFI bit of first VLAN tag in the outer header of the incoming packet. ;Valid only when outer_second_cvlan_tag ==1 or outer_sec;ond_svlan_tag ==1 */
	uint32_t outer_second_prio:3;		/* Priority of second VLAN tag in the outer header of the incoming ;packet. Valid only when outer_second_cvlan_tag ==1 or outer_sec;ond_svlan_tag ==1 */
	uint32_t gre_protocol:16;		/* GRE Protocol (outer) */
	uint32_t reserved_auto3:12;
	uint32_t inner_second_svlan_tag:1;	/* The second vlan in the inner header of the packet is s-vlan (0x8a88). ;inner_second_cvlan_tag and inner_second_svlan_tag cannot be set ;together */
	uint32_t outer_second_svlan_tag:1;	/* The second vlan in the outer header of the packet is s-vlan (0x8a88). ;outer_second_cvlan_tag and outer_second_svlan_tag cannot be set ;together */
	uint32_t inner_second_cvlan_tag:1;	/* The second vlan in the inner header of the packet is c-vlan (0x8100). ;inner_second_cvlan_tag and inner_second_svlan_tag cannot be set ;together */
	uint32_t outer_second_cvlan_tag:1;	/* The second vlan in the outer header of the packet is c-vlan (0x8100). ;outer_second_cvlan_tag and outer_second_svlan_tag cannot be set ;together */
	uint32_t gre_key_l:8;			/* GRE Key [7:0] (outer) */
	uint32_t gre_key_h:24;			/* GRE Key[31:8] (outer) */
	uint32_t reserved_auto4:8;
	uint32_t vxlan_vni:24;			/* VXLAN VNI (outer) */
	uint32_t geneve_oam:1;			/* GENEVE OAM field (outer) */
	uint32_t reserved_auto5:7;
	uint32_t geneve_vni:24;			/* GENEVE VNI field (outer) */
	uint32_t outer_ipv6_flow_label:20;	/* Flow label of incoming IPv6 packet (outer) */
	uint32_t reserved_auto6:12;
	uint32_t inner_ipv6_flow_label:20;	/* Flow label of incoming IPv6 packet (inner) */
	uint32_t reserved_auto7:12;
	uint32_t geneve_protocol_type:16;	/* GENEVE protocol type (outer) */
	uint32_t geneve_opt_len:6;		/* GENEVE OptLen (outer) */
	uint32_t reserved_auto8:10;
	uint32_t bth_dst_qp:24;			/* Destination QP in BTH header */
	uint32_t reserved_auto9:8;
	uint8_t reserved_auto10[20];
};

struct dr_match_misc2 {
	uint32_t outer_first_mpls_ttl:8;		/* First MPLS TTL (outer) */
	uint32_t outer_first_mpls_s_bos:1;		/* First MPLS S_BOS (outer) */
	uint32_t outer_first_mpls_exp:3;		/* First MPLS EXP (outer) */
	uint32_t outer_first_mpls_label:20;		/* First MPLS LABEL (outer) */
	uint32_t inner_first_mpls_ttl:8;		/* First MPLS TTL (inner) */
	uint32_t inner_first_mpls_s_bos:1;		/* First MPLS S_BOS (inner) */
	uint32_t inner_first_mpls_exp:3;		/* First MPLS EXP (inner) */
	uint32_t inner_first_mpls_label:20;		/* First MPLS LABEL (inner) */
	uint32_t outer_first_mpls_over_gre_ttl:8;	/* last MPLS TTL (outer) */
	uint32_t outer_first_mpls_over_gre_s_bos:1;	/* last MPLS S_BOS (outer) */
	uint32_t outer_first_mpls_over_gre_exp:3;	/* last MPLS EXP (outer) */
	uint32_t outer_first_mpls_over_gre_label:20;	/* last MPLS LABEL (outer) */
	uint32_t outer_first_mpls_over_udp_ttl:8;	/* last MPLS TTL (outer) */
	uint32_t outer_first_mpls_over_udp_s_bos:1;	/* last MPLS S_BOS (outer) */
	uint32_t outer_first_mpls_over_udp_exp:3;	/* last MPLS EXP (outer) */
	uint32_t outer_first_mpls_over_udp_label:20;	/* last MPLS LABEL (outer) */
	uint32_t metadata_reg_c_7;			/* metadata_reg_c_7 */
	uint32_t metadata_reg_c_6;			/* metadata_reg_c_6 */
	uint32_t metadata_reg_c_5;			/* metadata_reg_c_5 */
	uint32_t metadata_reg_c_4;			/* metadata_reg_c_4 */
	uint32_t metadata_reg_c_3;			/* metadata_reg_c_3 */
	uint32_t metadata_reg_c_2;			/* metadata_reg_c_2 */
	uint32_t metadata_reg_c_1;			/* metadata_reg_c_1 */
	uint32_t metadata_reg_c_0;			/* metadata_reg_c_0 */
	uint32_t metadata_reg_a;			/* metadata_reg_a */
	uint32_t metadata_reg_b;			/* metadata_reg_b */
	uint8_t reserved_auto2[8];
};

struct dr_match_misc3 {
	uint32_t inner_tcp_seq_num;
	uint32_t outer_tcp_seq_num;
	uint32_t inner_tcp_ack_num;
	uint32_t outer_tcp_ack_num;
	uint32_t outer_vxlan_gpe_vni:24;
	uint32_t reserved_auto1:8;
	uint32_t reserved_auto2:16;
	uint32_t outer_vxlan_gpe_flags:8;
	uint32_t outer_vxlan_gpe_next_protocol:8;
	uint32_t icmpv4_header_data;
	uint32_t icmpv6_header_data;
	uint32_t icmpv6_code:8;
	uint32_t icmpv6_type:8;
	uint32_t icmpv4_code:8;
	uint32_t icmpv4_type:8;
	uint8_t reserved_auto3[0x1c];
};

struct dr_match_param {
	struct dr_match_spec	outer;
	struct dr_match_misc	misc;
	struct dr_match_spec	inner;
	struct dr_match_misc2	misc2;
	struct dr_match_misc3	misc3;
};

#define DR_MASK_IS_FLEX_PARSER_ICMPV4_SET(_misc3) (_misc3->icmpv4_type || \
						   _misc3->icmpv4_code || \
						   _misc3->icmpv4_header_data)

struct dr_esw_caps {
	uint64_t drop_icm_address_rx;
	uint64_t drop_icm_address_tx;
	uint64_t uplink_icm_address_rx;
	uint64_t uplink_icm_address_tx;
	bool sw_owner;
};

struct dr_devx_vport_cap {
	uint16_t gvmi;
	uint64_t icm_address_rx;
	uint64_t icm_address_tx;
};

struct dr_devx_caps {
	uint16_t			gvmi;
	uint64_t			nic_rx_drop_address;
	uint64_t			nic_tx_drop_address;
	uint64_t			nic_tx_allow_address;
	uint64_t			esw_rx_drop_address;
	uint64_t			esw_tx_drop_address;
	uint32_t			log_icm_size;
	uint64_t			hdr_modify_icm_addr;
	uint32_t			flex_protocols;
	uint8_t				flex_parser_id_icmp_dw0;
	uint8_t				flex_parser_id_icmp_dw1;
	uint8_t				flex_parser_id_icmpv6_dw0;
	uint8_t				flex_parser_id_icmpv6_dw1;
	uint8_t				max_ft_level;
	bool				eswitch_manager;
	bool				rx_sw_owner;
	bool				tx_sw_owner;
	bool				fdb_sw_owner;
	uint32_t			num_vports;
	struct dr_devx_vport_cap	*vports_caps;
};

struct dr_domain_rx_tx {
	uint64_t		drop_icm_addr;
	uint64_t		default_icm_addr;
	enum dr_ste_entry_type	ste_type;
};

struct dr_domain_info {
	bool			supp_sw_steering;
	uint32_t		max_inline_size;
	uint32_t		max_send_wr;
	uint32_t		max_log_sw_icm_sz;
	uint32_t		max_log_action_icm_sz;
	struct dr_domain_rx_tx	rx;
	struct dr_domain_rx_tx	tx;
	struct ibv_device_attr	attr;
	struct dr_devx_caps	caps;
};

struct mlx5dv_dr_domain {
	struct ibv_context		*ctx;
	struct ibv_pd			*pd;
	struct mlx5dv_devx_uar		*uar;
	enum mlx5dv_dr_domain_type	type;
	atomic_int			refcount;
	pthread_mutex_t			mutex;
	struct dr_icm_pool		*ste_icm_pool;
	struct dr_icm_pool		*action_icm_pool;
	struct dr_send_ring		*send_ring;
	struct dr_domain_info		info;
};

struct dr_table_rx_tx {
	struct dr_ste_htbl		*s_anchor;
	struct dr_domain_rx_tx		*nic_dmn;
};

struct mlx5dv_dr_table {
	struct mlx5dv_dr_domain		*dmn;
	struct dr_table_rx_tx		rx;
	struct dr_table_rx_tx		tx;
	uint32_t			level;
	uint32_t			table_type;
	struct list_head		matcher_list;
	struct mlx5dv_devx_obj		*devx_obj;
	atomic_int			refcount;
};

struct dr_matcher_rx_tx {
	struct dr_ste_htbl		*s_htbl;
	struct dr_ste_htbl		*e_anchor;
	struct dr_ste_build		ste_builder[DR_RULE_MAX_STES];
	uint8_t				num_of_builders;
	uint64_t			default_icm_addr;
	struct dr_table_rx_tx		*nic_tbl;
};

struct mlx5dv_dr_matcher {
	struct mlx5dv_dr_table		*tbl;
	struct dr_matcher_rx_tx		rx;
	struct dr_matcher_rx_tx		tx;
	struct list_node		matcher_list;
	uint16_t			prio;
	struct dr_match_param		mask;
	uint8_t				match_criteria;
	atomic_int			refcount;
	struct mlx5dv_flow_matcher	*dv_matcher;
};

struct dr_rule_member {
	struct dr_ste		*ste;
	/* attached to dr_rule via this */
	struct list_node	list;
	/* attached to dr_ste via this */
	struct list_node	use_ste_list;
};

struct mlx5dv_dr_action {
	enum dr_action_type		action_type;
	atomic_int			refcount;
	union {
		struct {
			struct mlx5dv_dr_domain	*dmn;
			bool			is_root_level;
			union {
				struct ibv_flow_action	*flow_action; /* root*/
				struct {
					struct dr_icm_chunk	*chunk;
					uint8_t			*data;
					uint32_t		data_size;
					uint16_t		num_of_actions;
					uint32_t		index;
				};
			};
		} rewrite;
		struct {
			struct mlx5dv_dr_domain	*dmn;
			bool			is_root_level;
			union {
				struct ibv_flow_action	*flow_action; /* root*/
				struct {
					struct mlx5dv_devx_obj	*dvo;
					uint32_t		reformat_size;
				};
			};
		} reformat;
		struct mlx5dv_dr_table	*dest_tbl;
		struct {
			struct mlx5dv_devx_obj	*devx_obj;
			uint32_t		offeset;
		} ctr;
		struct {
			struct mlx5dv_dr_domain		*dmn;
			struct dr_devx_vport_cap	*caps;
			uint32_t			num;
		} vport;
		struct ibv_qp		*qp;
		struct mlx5dv_devx_obj	*devx_obj;
		uint32_t		flow_tag;
	};
};

enum dr_connect_type {
	CONNECT_HIT	= 1,
	CONNECT_MISS	= 2,
};

struct dr_htbl_connect_info {
	enum dr_connect_type type;
	union {
		struct dr_ste_htbl *hit_next_htbl;
		uint64_t miss_icm_addr;
	};
};


struct dr_rule_rx_tx {
	struct list_head		rule_members_list;
	struct dr_matcher_rx_tx		*nic_matcher;
};

struct mlx5dv_dr_rule {
	struct mlx5dv_dr_matcher	*matcher;
	union {
		struct {
			struct dr_rule_rx_tx	rx;
			struct dr_rule_rx_tx	tx;
		};
		struct ibv_flow *flow;
	};
	struct list_head	rule_actions_list;
};

void dr_rule_update_rule_member(struct dr_ste *new_ste, struct dr_ste *ste);

struct dr_icm_chunk {
	struct dr_icm_bucket	*bucket;
	struct list_node	chunk_list;
	uint32_t		rkey;
	uint32_t		num_of_entries;
	uint32_t		byte_size;
	uint64_t		icm_addr;
	uint64_t		mr_addr;

	/* Memory optimisation */
	struct dr_ste		*ste_arr;
	uint8_t			*hw_ste_arr;
	struct list_head	*miss_list;
};

static inline int dr_matcher_supp_flex_parser_icmp_v4(struct dr_devx_caps *caps)
{
	return caps->flex_protocols & MLX5_FLEX_PARSER_ICMP_V4_ENABLED;
}

static inline int dr_matcher_supp_flex_parser_icmp_v6(struct dr_devx_caps *caps)
{
	return caps->flex_protocols & MLX5_FLEX_PARSER_ICMP_V6_ENABLED;
}

static inline uint32_t
dr_icm_pool_chunk_size_to_entries(enum dr_icm_chunk_size chunk_size)
{
		return 1 << chunk_size;
}

static inline int
dr_icm_pool_chunk_size_to_byte(enum dr_icm_chunk_size chunk_size,
			       enum dr_icm_type icm_type)
{
	int num_of_entries;
	int entry_size;

	if (icm_type == DR_ICM_TYPE_STE)
		entry_size = DR_STE_SIZE;
	else
		entry_size = DR_MODIFY_ACTION_SIZE;

	num_of_entries = dr_icm_pool_chunk_size_to_entries(chunk_size);

	return entry_size * num_of_entries;
}

static inline struct dr_devx_vport_cap
*dr_get_vport_cap(struct dr_devx_caps *caps, uint32_t vport)
{
	if (!caps->vports_caps ||
	    (vport >= caps->num_vports && vport != WIRE_PORT)) {
		errno = EINVAL;
		return NULL;
	}

	return &caps->vports_caps[vport == WIRE_PORT ? caps->num_vports : vport];
}

/* internal API functions */
int dr_devx_query_device(struct ibv_context *ctx, struct dr_devx_caps *caps);
int dr_devx_query_esw_vport_context(struct ibv_context *ctx,
				    bool other_vport, uint16_t vport_number,
				    uint64_t *icm_address_rx,
				    uint64_t *icm_address_tx);
int dr_devx_query_gvmi(struct ibv_context *ctx,
		       bool other_vport, uint16_t vport_number, uint16_t *gvmi);
int dr_devx_query_esw_caps(struct ibv_context *ctx,
			   struct dr_esw_caps *caps);
int dr_devx_sync_steering(struct ibv_context *ctx);
struct mlx5dv_devx_obj *dr_devx_create_flow_table(struct ibv_context *ctx,
						  uint32_t table_type,
						  uint64_t icm_addr_rx,
						  uint64_t icm_addr_tx,
						  u8 level);
struct mlx5dv_devx_obj *dr_devx_create_reformat_ctx(struct ibv_context *ctx,
						    enum reformat_type rt,
						    size_t reformat_size,
						    void *reformat_data);
struct mlx5dv_devx_obj *dr_devx_create_cq(struct ibv_context *ctx,
					  uint32_t page_id,
					  uint32_t buff_umem_id,
					  uint32_t db_umem_id,
					  uint32_t eqn,
					  int ncqe,
					  int cqen);

struct dr_devx_qp_create_attr {
	uint32_t	page_id;
	uint32_t	pdn;
	uint32_t	cqn;
	uint32_t	pm_state;
	uint32_t	service_type;
	uint32_t	buff_umem_id;
	uint32_t	db_umem_id;
	uint32_t	sq_wqe_cnt;
	uint32_t	rq_wqe_cnt;
	uint32_t	rq_wqe_shift;
};

struct mlx5dv_devx_obj *dr_devx_create_qp(struct ibv_context *ctx,
					  struct dr_devx_qp_create_attr *attr);

int dr_devx_modify_qp_rst2init(struct ibv_context *ctx,
			       struct mlx5dv_devx_obj *qp_obj,
			       uint16_t port);

struct dr_gid_attr {
	union ibv_gid		gid;
	enum roce_version	roce_ver;
	uint8_t			mac[6];
};

struct dr_devx_qp_rtr_attr {
	struct dr_gid_attr	dgid_attr;
	enum ibv_mtu		mtu;
	uint16_t		qp_num;
	uint16_t		port_num;
	uint8_t			min_rnr_timer;
	uint8_t			sgid_index;
};

int dr_devx_modify_qp_init2rtr(struct ibv_context *ctx,
			       struct mlx5dv_devx_obj *qp_obj,
			       struct dr_devx_qp_rtr_attr *attr);

struct dr_devx_qp_rts_attr {
	uint8_t		timeout;
	uint8_t		retry_cnt;
	uint8_t		rnr_retry;
};

int dr_devx_modify_qp_rtr2rts(struct ibv_context *ctx,
			      struct mlx5dv_devx_obj *qp_obj,
			      struct dr_devx_qp_rts_attr *attr);
int dr_devx_query_gid(struct ibv_context *ctx, uint8_t vhca_port_num,
		      uint16_t index, struct dr_gid_attr *attr);

static inline bool dr_is_root_table(struct mlx5dv_dr_table *tbl)
{
	return tbl->level == 0;
}

struct dr_icm_pool *dr_icm_pool_create(struct mlx5dv_dr_domain *dmn,
				       enum dr_icm_type icm_type);
void dr_icm_pool_destroy(struct dr_icm_pool *pool);

struct dr_icm_chunk *dr_icm_alloc_chunk(struct dr_icm_pool *pool,
					enum dr_icm_chunk_size chunk_size);
void dr_icm_free_chunk(struct dr_icm_chunk *chunk);
bool dr_ste_is_not_valid_entry(uint8_t *p_hw_ste);
int dr_ste_htbl_init_and_postsend(struct mlx5dv_dr_domain *dmn,
				  struct dr_domain_rx_tx *nic_dmn,
				  struct dr_ste_htbl *htbl,
				  struct dr_htbl_connect_info *connect_info,
				  bool update_hw_ste);
void dr_ste_set_formated_ste(uint16_t gvmi,
			     struct dr_domain_rx_tx *nic_dmn,
			     struct dr_ste_htbl *htbl,
			     uint8_t *formated_ste,
			     struct dr_htbl_connect_info *connect_info);
void dr_ste_copy_param(uint8_t match_criteria,
		       struct dr_match_param *set_param,
		       struct mlx5dv_flow_match_parameters *mask);

void dr_crc32_init_table(void);
uint32_t dr_crc32_slice8_calc(const void *input_data, size_t length);

struct dr_wq {
	unsigned	*wqe_head;
	unsigned	wqe_cnt;
	unsigned	max_post;
	unsigned	head;
	unsigned	tail;
	unsigned	cur_post;
	int		max_gs;
	int		wqe_shift;
	int		offset;
	void		*qend;
};

struct dr_qp {
	struct mlx5_buf			buf;
	struct dr_wq			sq;
	struct dr_wq			rq;
	int				sq_size;
	void				*sq_start;
	int				max_inline_data;
	__be32				*db;
	struct mlx5dv_devx_obj		*obj;
	struct mlx5dv_devx_uar		*uar;
	struct mlx5dv_devx_umem		*buf_umem;
	struct mlx5dv_devx_umem		*db_umem;
};

struct dr_cq {
	uint8_t				*buf;
	uint32_t			cons_index;
	int				ncqe;
	struct dr_qp			*qp; /* Assume CQ per QP */
	__be32				*db;
	struct ibv_cq			*ibv_cq;
	uint32_t			cqn;
	uint32_t			cqe_sz;
};

#define MAX_SEND_CQE		64
#define MIN_READ_SYNC		64

struct dr_send_ring {
	struct dr_cq		cq;
	struct dr_qp		*qp;
	struct ibv_mr		*mr;
	/* How much wqes are waiting for completion */
	uint32_t		pending_wqe;
	/* Signal request per this trash hold value */
	uint16_t		signal_th;
	/* Each post_send_size less than max_post_send_size */
	uint32_t		max_post_send_size;
	/* manage the send queue */
	uint32_t		tx_head;
	void			*buf;
	uint32_t		buf_size;
	struct ibv_wc		wc[MAX_SEND_CQE];
	uint8_t			sync_buff[MIN_READ_SYNC];
	struct ibv_mr		*sync_mr;
};

int dr_send_ring_alloc(struct mlx5dv_dr_domain *dmn);
void dr_send_ring_free(struct dr_send_ring *send_ring);
int dr_send_ring_force_drain(struct mlx5dv_dr_domain *dmn);
int dr_send_postsend_ste(struct mlx5dv_dr_domain *dmn, struct dr_ste *ste,
			 uint8_t *data, uint16_t size, uint16_t offset);
int dr_send_postsend_htbl(struct mlx5dv_dr_domain *dmn, struct dr_ste_htbl *htbl,
			  uint8_t *formated_ste, uint8_t *mask);
int dr_send_postsend_formated_htbl(struct mlx5dv_dr_domain *dmn,
				   struct dr_ste_htbl *htbl,
				   uint8_t *ste_init_data,
				   bool update_hw_ste);
int dr_send_postsend_action(struct mlx5dv_dr_domain *dmn,
			    struct mlx5dv_dr_action *action);
#endif
