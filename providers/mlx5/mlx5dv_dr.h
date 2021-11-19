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
#include <ccan/bitmap.h>
#include <stdatomic.h>
#include "mlx5dv.h"
#include "mlx5_ifc.h"
#include "mlx5.h"

#define DR_RULE_MAX_STES	20
#define DR_ACTION_MAX_STES	7
#define DR_ACTION_ASO_CROSS_GVMI_STES 2
/* Use up to 14 send rings. This number provided the best performance */
#define DR_MAX_SEND_RINGS	14
#define NUM_OF_LOCKS		DR_MAX_SEND_RINGS
#define WIRE_PORT		0xFFFF
#define ECPF_PORT		0xFFFE
#define DR_STE_SVLAN		0x1
#define DR_STE_CVLAN		0x2
#define CVLAN_ETHERTYPE	0x8100
#define SVLAN_ETHERTYPE	0x88a8
#define NUM_OF_FLEX_PARSERS	8
#define DR_STE_MAX_FLEX_0_ID	3
#define DR_STE_MAX_FLEX_1_ID	7
#define DR_VPORTS_BUCKETS	256

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
	DR_STE_LU_TYPE_DONT_CARE	= 0x0f,
};

enum {
	DR_STE_SIZE		= 64,
	DR_STE_SIZE_CTRL	= 32,
	DR_STE_SIZE_MATCH_TAG	= 32,
	DR_STE_SIZE_TAG		= 16,
	DR_STE_SIZE_MASK	= 16,
	DR_STE_SIZE_REDUCED	= DR_STE_SIZE - DR_STE_SIZE_MASK,
	DR_STE_LOG_SIZE		= 6,
};

enum dr_ste_ctx_action_cap {
	DR_STE_CTX_ACTION_CAP_NONE	= 0,
	DR_STE_CTX_ACTION_CAP_TX_POP	= 1 << 0,
	DR_STE_CTX_ACTION_CAP_RX_PUSH	= 1 << 1,
	DR_STE_CTX_ACTION_CAP_RX_ENCAP	= 1 << 3,
};

enum {
	DR_MODIFY_ACTION_SIZE	= 8,
	DR_MODIFY_ACTION_LOG_SIZE	= 3,
};

enum dr_matcher_criteria {
	DR_MATCHER_CRITERIA_EMPTY	= 0,
	DR_MATCHER_CRITERIA_OUTER	= 1 << 0,
	DR_MATCHER_CRITERIA_MISC	= 1 << 1,
	DR_MATCHER_CRITERIA_INNER	= 1 << 2,
	DR_MATCHER_CRITERIA_MISC2	= 1 << 3,
	DR_MATCHER_CRITERIA_MISC3	= 1 << 4,
	DR_MATCHER_CRITERIA_MISC4	= 1 << 5,
	DR_MATCHER_CRITERIA_MISC5       = 1 << 6,
	DR_MATCHER_CRITERIA_MAX		= 1 << 7,
};

enum dr_matcher_definer {
	DR_MATCHER_DEFINER_0	= 0,
	DR_MATCHER_DEFINER_2	= 2,
	DR_MATCHER_DEFINER_6	= 6,
	DR_MATCHER_DEFINER_16	= 16,
	DR_MATCHER_DEFINER_22	= 22,
	DR_MATCHER_DEFINER_24	= 24,
	DR_MATCHER_DEFINER_25	= 25,
	DR_MATCHER_DEFINER_26	= 26,
	DR_MATCHER_DEFINER_28   = 28,
	DR_MATCHER_DEFINER_33   = 33,
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
	DR_ACTION_TYP_METER,
	DR_ACTION_TYP_MISS,
	DR_ACTION_TYP_SAMPLER,
	DR_ACTION_TYP_DEST_ARRAY,
	DR_ACTION_TYP_POP_VLAN,
	DR_ACTION_TYP_PUSH_VLAN,
	DR_ACTION_TYP_ASO_FIRST_HIT,
	DR_ACTION_TYP_ASO_FLOW_METER,
	DR_ACTION_TYP_ASO_CT,
	DR_ACTION_TYP_MAX,
};

struct dr_icm_pool;
struct dr_icm_chunk;
struct dr_icm_buddy_mem;
struct dr_ste_htbl;
struct dr_match_param;
struct dr_devx_caps;
struct dr_rule_rx_tx;
struct dr_matcher_rx_tx;
struct dr_ste_ctx;

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

	/* this ste is member of htbl */
	struct dr_ste_htbl	*htbl;

	struct dr_ste_htbl	*next_htbl;

	/* The rule this STE belongs to */
	struct dr_rule_rx_tx    *rule_rx_tx;

	/* this ste is part of a rule, located in ste's chain */
	uint8_t			ste_chain_location;
	uint8_t			size;
};

struct dr_ste_htbl_ctrl {
	/* total number of valid entries belonging to this hash table. This
	 * includes the non collision and collision entries
	 */
	int	num_of_valid_entries;

	/* total number of collisions entries attached to this table */
	int	num_of_collisions;
};

enum dr_ste_htbl_type {
	DR_STE_HTBL_TYPE_LEGACY		= 0,
	DR_STE_HTBL_TYPE_MATCH		= 1,
};

struct dr_ste_htbl {
	enum dr_ste_htbl_type	type;
	uint16_t		lu_type;
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
	uint16_t		lu_type;
	enum dr_ste_htbl_type	htbl_type;
	union {
		struct {
			uint16_t	byte_mask;
			uint8_t		bit_mask[DR_STE_SIZE_MASK];
		};
		struct {
			uint16_t		format_id;
			uint8_t			match[DR_STE_SIZE_MATCH_TAG];
			struct mlx5dv_devx_obj	*definer_obj;
		};
	};
	int (*ste_build_tag_func)(struct dr_match_param *spec,
				  struct dr_ste_build *sb,
				  uint8_t *tag);
};

struct dr_ste_htbl *dr_ste_htbl_alloc(struct dr_icm_pool *pool,
				      enum dr_icm_chunk_size chunk_size,
				      enum dr_ste_htbl_type type,
				      uint16_t lu_type, uint16_t byte_mask);
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
void dr_ste_set_miss_addr(struct dr_ste_ctx *ste_ctx, uint8_t *hw_ste_p,
			  uint64_t miss_addr);
void dr_ste_set_hit_addr_by_next_htbl(struct dr_ste_ctx *ste_ctx,
				      uint8_t *hw_ste,
				      struct dr_ste_htbl *next_htbl);
void dr_ste_set_hit_addr(struct dr_ste_ctx *ste_ctx, uint8_t *hw_ste_p,
			 uint64_t icm_addr, uint32_t ht_size);
void dr_ste_set_hit_gvmi(struct dr_ste_ctx *ste_ctx, uint8_t *hw_ste_p,
			 uint16_t gvmi);
void dr_ste_set_bit_mask(uint8_t *hw_ste_p, struct dr_ste_build *sb);
bool dr_ste_is_last_in_rule(struct dr_matcher_rx_tx *nic_matcher,
			    uint8_t ste_location);
uint64_t dr_ste_get_icm_addr(struct dr_ste *ste);
uint64_t dr_ste_get_mr_addr(struct dr_ste *ste);
struct list_head *dr_ste_get_miss_list(struct dr_ste *ste);
struct dr_ste *dr_ste_get_miss_list_top(struct dr_ste *ste);

static inline int dr_ste_tag_sz(struct dr_ste *ste)
{
	if (ste->htbl->type == DR_STE_HTBL_TYPE_LEGACY)
		return DR_STE_SIZE_TAG;

	return DR_STE_SIZE_MATCH_TAG;
}

#define MAX_VLANS 2

struct dr_aso_cross_dmn_arrays {
	struct dr_ste_htbl **action_htbl;
	struct dr_ste_htbl **rule_htbl;
};

struct dr_action_aso {
	struct mlx5dv_dr_domain *dmn;
	struct mlx5dv_devx_obj *devx_obj;
	uint32_t offset;
	uint8_t dest_reg_id;
	union {
		struct {
			bool set;
		} first_hit;
		struct {
			uint8_t initial_color;
		} flow_meter;
		struct {
			bool direction;
		} ct;
	};
};

struct dr_ste_actions_attr {
	uint32_t	modify_index;
	uint16_t	modify_actions;
	uint32_t	decap_index;
	uint16_t	decap_actions;
	bool		decap_with_vlan;
	uint64_t	final_icm_addr;
	uint32_t	flow_tag;
	uint32_t	ctr_id;
	uint16_t	gvmi;
	uint16_t	hit_gvmi;
	uint32_t	reformat_id;
	uint32_t	reformat_size;
	bool		prio_tag_required;
	struct {
		int		count;
		uint32_t	headers[MAX_VLANS];
	} vlans;
	struct dr_action_aso *aso;
	uint32_t aso_ste_loc;
};

struct cross_dmn_params {
	uint32_t cross_dmn_loc;
	struct mlx5dv_dr_action *cross_dmn_action;
};

void dr_ste_set_actions_rx(struct dr_ste_ctx *ste_ctx,
			   uint8_t *action_type_set,
			   uint8_t *last_ste,
			   struct dr_ste_actions_attr *attr,
			   uint32_t *added_stes);
void dr_ste_set_actions_tx(struct dr_ste_ctx *ste_ctx,
			   uint8_t *action_type_set,
			   uint8_t *last_ste,
			   struct dr_ste_actions_attr *attr,
			   uint32_t *added_stes);
void dr_ste_set_action_set(struct dr_ste_ctx *ste_ctx,
			   __be64 *hw_action,
			   uint8_t hw_field,
			   uint8_t shifter,
			   uint8_t length,
			   uint32_t data);
void dr_ste_set_action_add(struct dr_ste_ctx *ste_ctx,
			   __be64 *hw_action,
			   uint8_t hw_field,
			   uint8_t shifter,
			   uint8_t length,
			   uint32_t data);
void dr_ste_set_action_copy(struct dr_ste_ctx *ste_ctx,
			    __be64 *hw_action,
			    uint8_t dst_hw_field,
			    uint8_t dst_shifter,
			    uint8_t dst_len,
			    uint8_t src_hw_field,
			    uint8_t src_shifter);
int dr_ste_set_action_decap_l3_list(struct dr_ste_ctx *ste_ctx,
				   void *data, uint32_t data_sz,
				   uint8_t *hw_action, uint32_t hw_action_sz,
				   uint16_t *used_hw_action_num);
void dr_ste_v1_set_aso_ct(uint8_t *d_action,
			  uint32_t object_id,
			  uint32_t offset,
			  uint8_t dest_reg_id,
			  bool direction);
const struct dr_ste_action_modify_field *
dr_ste_conv_modify_hdr_sw_field(struct dr_ste_ctx *ste_ctx,
				struct dr_devx_caps *caps,
				uint16_t sw_field);

struct dr_ste_ctx *dr_ste_get_ctx(uint8_t version);
void dr_ste_free(struct dr_ste *ste,
		 struct mlx5dv_dr_rule *rule,
		 struct dr_rule_rx_tx *nic_rule);
static inline void dr_ste_put(struct dr_ste *ste,
			      struct mlx5dv_dr_rule *rule,
			      struct dr_rule_rx_tx *nic_rule)
{
	if (atomic_fetch_sub(&ste->refcount, 1) == 1)
		dr_ste_free(ste, rule, nic_rule);
}

/* initial as 0, increased only when ste appears in a new rule */
static inline void dr_ste_get(struct dr_ste *ste)
{
	atomic_fetch_add(&ste->refcount, 1);
}

static inline bool dr_ste_is_not_used(struct dr_ste *ste)
{
	return !atomic_load(&ste->refcount);
}

bool dr_ste_equal_tag(void *src, void *dst, uint8_t tag_size);
int dr_ste_create_next_htbl(struct mlx5dv_dr_matcher *matcher,
			    struct dr_matcher_rx_tx *nic_matcher,
			    struct dr_ste *ste,
			    uint8_t *cur_hw_ste,
			    enum dr_icm_chunk_size log_table_size,
			    uint8_t send_ring_idx);

/* STE build functions */
int dr_ste_build_pre_check(struct mlx5dv_dr_domain *dmn,
			   uint8_t match_criteria,
			   struct dr_match_param *mask,
			   struct dr_match_param *value);
int dr_ste_build_ste_arr(struct mlx5dv_dr_matcher *matcher,
			 struct dr_matcher_rx_tx *nic_matcher,
			 struct dr_match_param *value,
			 uint8_t *ste_arr);
void dr_ste_build_eth_l2_src_dst(struct dr_ste_ctx *ste_ctx,
				 struct dr_ste_build *sb,
				 struct dr_match_param *mask,
				 bool inner, bool rx);
void dr_ste_build_eth_l3_ipv4_5_tuple(struct dr_ste_ctx *ste_ctx,
				      struct dr_ste_build *sb,
				      struct dr_match_param *mask,
				      bool inner, bool rx);
void dr_ste_build_eth_l3_ipv4_misc(struct dr_ste_ctx *ste_ctx,
				   struct dr_ste_build *sb,
				   struct dr_match_param *mask,
				   bool inner, bool rx);
void dr_ste_build_eth_l3_ipv6_dst(struct dr_ste_ctx *ste_ctx,
				  struct dr_ste_build *sb,
				  struct dr_match_param *mask,
				  bool inner, bool rx);
void dr_ste_build_eth_l3_ipv6_src(struct dr_ste_ctx *ste_ctx,
				  struct dr_ste_build *sb,
				  struct dr_match_param *mask,
				  bool inner, bool rx);
void dr_ste_build_eth_l2_src(struct dr_ste_ctx *ste_ctx,
			     struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx);
void dr_ste_build_eth_l2_dst(struct dr_ste_ctx *ste_ctx,
			     struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx);
void dr_ste_build_eth_l2_tnl(struct dr_ste_ctx *ste_ctx,
			     struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx);
void dr_ste_build_eth_ipv6_l3_l4(struct dr_ste_ctx *ste_ctx,
				 struct dr_ste_build *sb,
				 struct dr_match_param *mask,
				 bool inner, bool rx);
void dr_ste_build_eth_l4_misc(struct dr_ste_ctx *ste_ctx,
			      struct dr_ste_build *sb,
			      struct dr_match_param *mask,
			      bool inner, bool rx);
void dr_ste_build_tnl_gre(struct dr_ste_ctx *ste_ctx,
			  struct dr_ste_build *sb,
			  struct dr_match_param *mask,
			  bool inner, bool rx);
void dr_ste_build_mpls(struct dr_ste_ctx *ste_ctx,
		       struct dr_ste_build *sb,
		       struct dr_match_param *mask,
		       bool inner, bool rx);
void dr_ste_build_tnl_mpls_over_gre(struct dr_ste_ctx *ste_ctx,
				    struct dr_ste_build *sb,
				    struct dr_match_param *mask,
				    struct dr_devx_caps *caps,
				    bool inner, bool rx);
void dr_ste_build_tnl_mpls_over_udp(struct dr_ste_ctx *ste_ctx,
				    struct dr_ste_build *sb,
				    struct dr_match_param *mask,
				    struct dr_devx_caps *caps,
				    bool inner, bool rx);
void dr_ste_build_icmp(struct dr_ste_ctx *ste_ctx,
		       struct dr_ste_build *sb,
		       struct dr_match_param *mask,
		       struct dr_devx_caps *caps,
		       bool inner, bool rx);
void dr_ste_build_tnl_vxlan_gpe(struct dr_ste_ctx *ste_ctx,
				struct dr_ste_build *sb,
				struct dr_match_param *mask,
				bool inner, bool rx);
void dr_ste_build_tnl_geneve(struct dr_ste_ctx *ste_ctx,
			     struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx);
void dr_ste_build_tnl_geneve_tlv_opt(struct dr_ste_ctx *ste_ctx,
				     struct dr_ste_build *sb,
				     struct dr_match_param *mask,
				     struct dr_devx_caps *caps,
				     bool inner, bool rx);
void dr_ste_build_tnl_gtpu(struct dr_ste_ctx *ste_ctx,
			   struct dr_ste_build *sb,
			   struct dr_match_param *mask,
			   bool inner, bool rx);
void dr_ste_build_tnl_gtpu_flex_parser_0(struct dr_ste_ctx *ste_ctx,
					 struct dr_ste_build *sb,
					 struct dr_match_param *mask,
					 struct dr_devx_caps *caps,
					 bool inner, bool rx);
void dr_ste_build_tnl_gtpu_flex_parser_1(struct dr_ste_ctx *ste_ctx,
					 struct dr_ste_build *sb,
					 struct dr_match_param *mask,
					 struct dr_devx_caps *caps,
					 bool inner, bool rx);
void dr_ste_build_general_purpose(struct dr_ste_ctx *ste_ctx,
				  struct dr_ste_build *sb,
				  struct dr_match_param *mask,
				  bool inner, bool rx);
void dr_ste_build_register_0(struct dr_ste_ctx *ste_ctx,
			     struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx);
void dr_ste_build_register_1(struct dr_ste_ctx *ste_ctx,
			     struct dr_ste_build *sb,
			     struct dr_match_param *mask,
			     bool inner, bool rx);
void dr_ste_build_src_gvmi_qpn(struct dr_ste_ctx *ste_ctx,
			       struct dr_ste_build *sb,
			       struct dr_match_param *mask,
			       struct dr_devx_caps *caps,
			       bool inner, bool rx);
void dr_ste_build_flex_parser_0(struct dr_ste_ctx *ste_ctx,
				struct dr_ste_build *sb,
				struct dr_match_param *mask,
				bool inner, bool rx);
void dr_ste_build_flex_parser_1(struct dr_ste_ctx *ste_ctx,
				struct dr_ste_build *sb,
				struct dr_match_param *mask,
				bool inner, bool rx);
void dr_ste_build_tunnel_header_0_1(struct dr_ste_ctx *ste_ctx,
				    struct dr_ste_build *sb,
				    struct dr_match_param *mask,
				    bool inner, bool rx);
int dr_ste_build_def0(struct dr_ste_ctx *ste_ctx,
		      struct dr_ste_build *sb,
		      struct dr_match_param *mask,
		      struct dr_devx_caps *caps,
		      bool inner, bool rx);
int dr_ste_build_def2(struct dr_ste_ctx *ste_ctx,
		      struct dr_ste_build *sb,
		      struct dr_match_param *mask,
		      struct dr_devx_caps *caps,
		      bool inner, bool rx);
int dr_ste_build_def6(struct dr_ste_ctx *ste_ctx,
		      struct dr_ste_build *sb,
		      struct dr_match_param *mask,
		      bool inner, bool rx);
int dr_ste_build_def16(struct dr_ste_ctx *ste_ctx,
		       struct dr_ste_build *sb,
		       struct dr_match_param *mask,
		       struct dr_devx_caps *caps,
		       bool inner, bool rx);
int dr_ste_build_def22(struct dr_ste_ctx *ste_ctx,
		       struct dr_ste_build *sb,
		       struct dr_match_param *mask,
		       bool inner, bool rx);
int dr_ste_build_def24(struct dr_ste_ctx *ste_ctx,
		       struct dr_ste_build *sb,
		       struct dr_match_param *mask,
		       bool inner, bool rx);
int dr_ste_build_def25(struct dr_ste_ctx *ste_ctx,
		       struct dr_ste_build *sb,
		       struct dr_match_param *mask,
		       bool inner, bool rx);
int dr_ste_build_def26(struct dr_ste_ctx *ste_ctx,
		       struct dr_ste_build *sb,
		       struct dr_match_param *mask,
		       bool inner, bool rx);
int dr_ste_build_def28(struct dr_ste_ctx *ste_ctx,
		       struct dr_ste_build *sb,
		       struct dr_match_param *mask,
		       bool inner, bool rx);
int dr_ste_build_def33(struct dr_ste_ctx *ste_ctx,
		       struct dr_ste_build *sb,
		       struct dr_match_param *mask,
		       bool inner, bool rx);
void dr_ste_build_empty_always_hit(struct dr_ste_build *sb, bool rx);

/* Actions utils */
int dr_actions_build_ste_arr(struct mlx5dv_dr_matcher *matcher,
			     struct dr_matcher_rx_tx *nic_matcher,
			     struct mlx5dv_dr_action *actions[],
			     uint32_t num_actions,
			     uint8_t *ste_arr,
			     uint32_t *new_hw_ste_arr_sz,
			     struct cross_dmn_params *cross_dmn_p);
int dr_actions_build_attr(struct mlx5dv_dr_matcher *matcher,
			  struct mlx5dv_dr_action *actions[],
			  size_t num_actions,
			  struct mlx5dv_flow_action_attr *attr,
			  struct mlx5_flow_action_attr_aux *attr_aux);

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
	uint32_t ipv4_ihl:4;
	uint32_t l3_ok:1;
	uint32_t l4_ok:1;
	uint32_t ipv4_checksum_ok:1;
	uint32_t l4_checksum_ok:1;
	uint32_t ip_ttl_hoplimit:8;
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
	uint32_t gre_c_present:1;		/* used with GRE, checksum exist when gre_c_present == 1 */
	uint32_t source_port:16;		/* Source port.;0xffff determines wire port */
	uint32_t inner_second_vid:12;		/* VLAN ID of first VLAN tag the inner header of the incoming packet. ;Valid only when inner_second_cvlan_tag ==1 or inner_sec;ond_svlan_tag ==1 */
	uint32_t inner_second_cfi:1;		/* CFI bit of first VLAN tag in the inner header of the incoming packet. ;Valid only when inner_second_cvlan_tag ==1 or inner_sec;ond_svlan_tag ==1 */
	uint32_t inner_second_prio:3;		/* Priority of second VLAN tag in the inner header of the incoming ;packet. Valid only when inner_second_cvlan_tag ==1 or inner_sec;ond_svlan_tag ==1 */
	uint32_t outer_second_vid:12;		/* VLAN ID of first VLAN tag the outer header of the incoming packet. ;Valid only when outer_second_cvlan_tag ==1 or outer_sec;ond_svlan_tag ==1 */
	uint32_t outer_second_cfi:1;		/* CFI bit of first VLAN tag in the outer header of the incoming packet. ;Valid only when outer_second_cvlan_tag ==1 or outer_sec;ond_svlan_tag ==1 */
	uint32_t outer_second_prio:3;		/* Priority of second VLAN tag in the outer header of the incoming ;packet. Valid only when outer_second_cvlan_tag ==1 or outer_sec;ond_svlan_tag ==1 */
	uint32_t gre_protocol:16;		/* GRE Protocol (outer) */
	uint32_t inner_second_svlan_tag:1;	/* The second vlan in the inner header of the packet is s-vlan (0x8a88). ;inner_second_cvlan_tag and inner_second_svlan_tag cannot be set ;together */
	uint32_t outer_second_svlan_tag:1;	/* The second vlan in the outer header of the packet is s-vlan (0x8a88). ;outer_second_cvlan_tag and outer_second_svlan_tag cannot be set ;together */
	uint32_t inner_second_cvlan_tag:1;	/* The second vlan in the inner header of the packet is c-vlan (0x8100). ;inner_second_cvlan_tag and inner_second_svlan_tag cannot be set ;together */
	uint32_t outer_second_cvlan_tag:1;	/* The second vlan in the outer header of the packet is c-vlan (0x8100). ;outer_second_cvlan_tag and outer_second_svlan_tag cannot be set ;together */
	uint32_t gre_key_l:8;			/* GRE Key [7:0] (outer) */
	uint32_t gre_key_h:24;			/* GRE Key[31:8] (outer) */
	uint32_t vxlan_vni:24;			/* VXLAN VNI (outer) */
	uint32_t geneve_oam:1;			/* GENEVE OAM field (outer) */
	uint32_t geneve_vni:24;			/* GENEVE VNI field (outer) */
	uint32_t outer_ipv6_flow_label:20;	/* Flow label of incoming IPv6 packet (outer) */
	uint32_t inner_ipv6_flow_label:20;	/* Flow label of incoming IPv6 packet (inner) */
	uint32_t geneve_protocol_type:16;	/* GENEVE protocol type (outer) */
	uint32_t geneve_opt_len:6;		/* GENEVE OptLen (outer) */
	uint32_t bth_dst_qp:24;			/* Destination QP in BTH header */
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
};

struct dr_match_misc3 {
	uint32_t inner_tcp_seq_num;
	uint32_t outer_tcp_seq_num;
	uint32_t inner_tcp_ack_num;
	uint32_t outer_tcp_ack_num;
	uint32_t outer_vxlan_gpe_vni:24;
	uint32_t outer_vxlan_gpe_flags:8;
	uint32_t outer_vxlan_gpe_next_protocol:8;
	uint32_t icmpv4_header_data;
	uint32_t icmpv6_header_data;
	uint8_t icmpv6_code;
	uint8_t icmpv6_type;
	uint8_t icmpv4_code;
	uint8_t icmpv4_type;
	uint32_t geneve_tlv_option_0_data;
	uint32_t gtpu_teid;
	uint32_t gtpu_msg_type:8;
	uint32_t gtpu_msg_flags:8;
	uint32_t gtpu_dw_2;
	uint32_t gtpu_first_ext_dw_0;
	uint32_t gtpu_dw_0;
};

struct dr_match_misc4 {
	uint32_t prog_sample_field_value_0;
	uint32_t prog_sample_field_id_0;
	uint32_t prog_sample_field_value_1;
	uint32_t prog_sample_field_id_1;
	uint32_t prog_sample_field_value_2;
	uint32_t prog_sample_field_id_2;
	uint32_t prog_sample_field_value_3;
	uint32_t prog_sample_field_id_3;
	uint32_t prog_sample_field_value_4;
	uint32_t prog_sample_field_id_4;
	uint32_t prog_sample_field_value_5;
	uint32_t prog_sample_field_id_5;
	uint32_t prog_sample_field_value_6;
	uint32_t prog_sample_field_id_6;
	uint32_t prog_sample_field_value_7;
	uint32_t prog_sample_field_id_7;
};

struct dr_match_misc5 {
	uint32_t macsec_tag_0;
	uint32_t macsec_tag_1;
	uint32_t macsec_tag_2;
	uint32_t macsec_tag_3;
	uint32_t tunnel_header_0;
	uint32_t tunnel_header_1;
	uint32_t tunnel_header_2;
	uint32_t tunnel_header_3;
	uint32_t reserved[0x8];
};

struct dr_match_param {
	struct dr_match_spec	outer;
	struct dr_match_misc	misc;
	struct dr_match_spec	inner;
	struct dr_match_misc2	misc2;
	struct dr_match_misc3	misc3;
	struct dr_match_misc4	misc4;
	struct dr_match_misc5	misc5;
};

#define DR_MASK_IS_ICMPV4_SET(_misc3) ((_misc3)->icmpv4_type || \
				       (_misc3)->icmpv4_code || \
				       (_misc3)->icmpv4_header_data)

struct dr_esw_caps {
	uint64_t drop_icm_address_rx;
	uint64_t drop_icm_address_tx;
	uint64_t uplink_icm_address_rx;
	uint64_t uplink_icm_address_tx;
	bool sw_owner;
	bool sw_owner_v2;
};

struct dr_devx_vport_cap {
	uint16_t vport_gvmi;
	uint16_t vhca_gvmi;
	uint64_t icm_address_rx;
	uint64_t icm_address_tx;
	uint16_t num;
	uint32_t metadata_c;
	uint32_t metadata_c_mask;
	/* locate vports table */
	struct dr_devx_vport_cap *next;
};

struct dr_devx_roce_cap {
	bool roce_en;
	bool fl_rc_qp_when_roce_disabled;
	bool fl_rc_qp_when_roce_enabled;
	uint8_t qp_ts_format;
};

struct dr_vports_table {
	struct dr_devx_vport_cap *buckets[DR_VPORTS_BUCKETS];
};

struct dr_devx_vports {
	/* E-Switch manager */
	struct dr_devx_vport_cap	esw_mngr;
	/* Uplink */
	struct dr_devx_vport_cap	wire;
	/* PF + VFS + SF */
	struct dr_vports_table		*vports;
	/* IB ports to vport + other_vports */
	struct dr_devx_vport_cap	**ib_ports;
	/* Number of vports PF + VFS + SFS + WIRE */
	uint32_t			num_ports;
	/* Protect vport query and add*/
	pthread_spinlock_t		lock;
};

struct dr_devx_caps {
	struct mlx5dv_dr_domain		*dmn;
	uint16_t			gvmi;
	uint64_t			nic_rx_drop_address;
	uint64_t			nic_tx_drop_address;
	uint64_t			nic_tx_allow_address;
	uint64_t			esw_rx_drop_address;
	uint64_t			esw_tx_drop_address;
	uint32_t			log_icm_size;
	uint8_t				log_modify_hdr_icm_size;
	uint64_t			hdr_modify_icm_addr;
	uint32_t			flex_protocols;
	uint8_t				flex_parser_header_modify;
	uint8_t				flex_parser_id_icmp_dw0;
	uint8_t				flex_parser_id_icmp_dw1;
	uint8_t				flex_parser_id_icmpv6_dw0;
	uint8_t				flex_parser_id_icmpv6_dw1;
	uint8_t				flex_parser_id_geneve_opt_0;
	uint8_t				flex_parser_id_mpls_over_gre;
	uint8_t				flex_parser_id_mpls_over_udp;
	uint8_t				flex_parser_id_gtpu_dw_0;
	uint8_t				flex_parser_id_gtpu_teid;
	uint8_t				flex_parser_id_gtpu_dw_2;
	uint8_t				flex_parser_id_gtpu_first_ext_dw_0;
	uint8_t				definer_supp_checksum;
	uint8_t				max_ft_level;
	uint8_t				sw_format_ver;
	bool				isolate_vl_tc;
	bool				eswitch_manager;
	bool				rx_sw_owner;
	bool				tx_sw_owner;
	bool				fdb_sw_owner;
	bool				rx_sw_owner_v2;
	bool				tx_sw_owner_v2;
	bool				fdb_sw_owner_v2;
	struct dr_devx_roce_cap		roce_caps;
	uint64_t			definer_format_sup;
	bool				prio_tag_required;
	bool				is_ecpf;
	struct dr_devx_vports		vports;
};

struct dr_devx_flow_table_attr {
	uint8_t		type;
	uint8_t		level;
	bool		sw_owner;
	bool		term_tbl;
	bool		reformat_en;
	uint64_t	icm_addr_rx;
	uint64_t	icm_addr_tx;
};

struct dr_devx_flow_group_attr {
	uint32_t	table_id;
	uint32_t	table_type;
};

struct dr_devx_flow_dest_info {
	enum dr_devx_flow_dest_type type;
	union {
		uint32_t vport_num;
		uint32_t tir_num;
		uint32_t counter_id;
		uint32_t ft_id;
	};
	bool has_reformat;
	uint32_t reformat_id;
};

struct dr_devx_flow_fte_attr {
	uint32_t			table_id;
	uint32_t			table_type;
	uint32_t			group_id;
	uint32_t			flow_tag;
	uint32_t			action;
	uint32_t			dest_size;
	struct dr_devx_flow_dest_info	*dest_arr;
	bool				extended_dest;
};

struct dr_devx_tbl {
	uint8_t			type;
	uint8_t			level;
	struct mlx5dv_devx_obj	*ft_dvo;
	struct mlx5dv_devx_obj	*fg_dvo;
	struct mlx5dv_devx_obj	*fte_dvo;
};

struct dr_devx_flow_sampler_attr {
	uint8_t		table_type;
	uint8_t		level;
	uint8_t		ignore_flow_level;
	uint32_t	sample_ratio;
	uint32_t	default_next_table_id;
	uint32_t	sample_table_id;
};

enum dr_domain_nic_type {
	DR_DOMAIN_NIC_TYPE_RX,
	DR_DOMAIN_NIC_TYPE_TX,
};

struct dr_domain_rx_tx {
	uint64_t		drop_icm_addr;
	uint64_t		default_icm_addr;
	enum dr_domain_nic_type	type;
	/* protect rx/tx domain */
	pthread_spinlock_t	locks[NUM_OF_LOCKS];
};

struct dr_domain_info {
	bool			supp_sw_steering;
	uint32_t		max_inline_size;
	uint32_t		max_log_sw_icm_sz;
	uint32_t		max_log_action_icm_sz;
	uint32_t		max_send_size;
	struct dr_domain_rx_tx	rx;
	struct dr_domain_rx_tx	tx;
	struct ibv_device_attr_ex attr;
	struct dr_devx_caps	caps;
	bool			use_mqs;
};

enum dr_domain_flags {
	 DR_DOMAIN_FLAG_MEMORY_RECLAIM = 1 << 0,
	 DR_DOMAIN_FLAG_DISABLE_DUPLICATE_RULES = 1 << 1,
};

struct mlx5dv_dr_domain {
	struct ibv_context		*ctx;
	struct dr_ste_ctx		*ste_ctx;
	struct ibv_pd			*pd;
	struct mlx5dv_devx_uar		*uar;
	enum mlx5dv_dr_domain_type	type;
	atomic_int			refcount;
	struct dr_icm_pool		*ste_icm_pool;
	struct dr_icm_pool		*action_icm_pool;
	struct dr_send_ring		*send_ring[DR_MAX_SEND_RINGS];
	struct dr_domain_info		info;
	struct list_head		tbl_list;
	uint32_t			flags;
	/* protect debug lists of all tracked objects */
	pthread_spinlock_t		debug_lock;
};

static inline int dr_domain_nic_lock_init(struct dr_domain_rx_tx *nic_dmn)
{
	int ret;
	int i;

	for (i = 0; i < NUM_OF_LOCKS; i++) {
		ret = pthread_spin_init(&nic_dmn->locks[i], PTHREAD_PROCESS_PRIVATE);
		if (ret) {
			errno = ret;
			goto destroy_locks;
		}
	}
	return 0;

destroy_locks:
	while (i--)
		pthread_spin_destroy(&nic_dmn->locks[i]);

	return ret;
}

static inline void dr_domain_nic_lock_uninit(struct dr_domain_rx_tx *nic_dmn)
{
	int i;

	for (i = 0; i < NUM_OF_LOCKS; i++)
		pthread_spin_destroy(&nic_dmn->locks[i]);
}

static inline void dr_domain_nic_lock(struct dr_domain_rx_tx *nic_dmn)
{
	int i;

	for (i = 0; i < NUM_OF_LOCKS; i++)
		pthread_spin_lock(&nic_dmn->locks[i]);
}

static inline void dr_domain_nic_unlock(struct dr_domain_rx_tx *nic_dmn)
{
	int i;

	for (i = 0; i < NUM_OF_LOCKS; i++)
		pthread_spin_unlock(&nic_dmn->locks[i]);
}

static inline void dr_domain_lock(struct mlx5dv_dr_domain *dmn)
{
	dr_domain_nic_lock(&dmn->info.rx);
	dr_domain_nic_lock(&dmn->info.tx);
}

static inline void dr_domain_unlock(struct mlx5dv_dr_domain *dmn)
{
	dr_domain_nic_unlock(&dmn->info.tx);
	dr_domain_nic_unlock(&dmn->info.rx);
}

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
	struct list_node		tbl_list;
};

struct dr_matcher_rx_tx {
	struct dr_ste_htbl		*s_htbl;
	struct dr_ste_htbl		*e_anchor;
	struct dr_ste_build		ste_builder[DR_RULE_MAX_STES];
	uint8_t				num_of_builders;
	uint64_t			default_icm_addr;
	struct dr_table_rx_tx		*nic_tbl;
	bool				fixed_size;
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
	struct list_head		rule_list;
};

struct dr_ste_action_modify_field {
	uint16_t hw_field;
	uint8_t start;
	uint8_t end;
	uint8_t l3_type;
	uint8_t l4_type;
	uint32_t flags;
};

struct dr_devx_tbl_with_refs {
	uint16_t		ref_actions_num;
	struct mlx5dv_dr_action	**ref_actions;
	struct dr_devx_tbl	*devx_tbl;
};

struct dr_flow_sampler {
	struct mlx5dv_devx_obj	*devx_obj;
	uint64_t		rx_icm_addr;
	uint64_t		tx_icm_addr;
	struct mlx5dv_dr_table	*next_ft;
};

struct dr_flow_sampler_restore_tbl {
	struct mlx5dv_dr_table		*tbl;
	struct mlx5dv_dr_matcher	*matcher;
	struct mlx5dv_dr_rule		*rule;
	struct mlx5dv_dr_action		**actions;
	uint16_t			num_of_actions;
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
					bool			allow_rx;
					bool			allow_tx;
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
		struct {
			struct mlx5dv_dr_table	*next_ft;
			struct mlx5dv_devx_obj	*devx_obj;
			uint64_t		rx_icm_addr;
			uint64_t		tx_icm_addr;
		} meter;
		struct {
			struct mlx5dv_dr_domain			*dmn;
			struct dr_devx_tbl_with_refs		*term_tbl;
			struct dr_flow_sampler			*sampler_default;
			struct dr_flow_sampler_restore_tbl	*restore_tbl;
			struct dr_flow_sampler			*sampler_restore;
		} sampler;
		struct mlx5dv_dr_table	*dest_tbl;
		struct {
			struct mlx5dv_dr_domain		*dmn;
			struct list_head		actions_list;
			struct dr_devx_tbl		*devx_tbl;
			uint64_t			rx_icm_addr;
			uint64_t			tx_icm_addr;
		} dest_array;
		struct {
			struct mlx5dv_devx_obj	*devx_obj;
			uint32_t		offset;
		} ctr;
		struct {
			struct mlx5dv_dr_domain		*dmn;
			struct dr_devx_vport_cap	*caps;
		} vport;
		struct {
			uint32_t	vlan_hdr;
		} push_vlan;
		struct {
			bool    is_qp;
			union {
				struct mlx5dv_devx_obj  *devx_tir;
				struct ibv_qp           *qp;
			};
		} dest_qp;
		struct dr_action_aso	aso;
		struct mlx5dv_devx_obj	*devx_obj;
		uint32_t		flow_tag;
	};
};

struct dr_rule_action_member {
	struct mlx5dv_dr_action *action;
	struct list_node	list;
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
	struct dr_matcher_rx_tx		*nic_matcher;
	struct dr_ste			*last_rule_ste;
	uint8_t				lock_index;
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
	struct list_node	rule_list;
	struct mlx5dv_dr_action	**actions;
	uint16_t		num_actions;
};

static inline void
dr_rule_lock(struct dr_rule_rx_tx *nic_rule, uint8_t *hw_ste)
{
	struct dr_matcher_rx_tx *nic_matcher = nic_rule->nic_matcher;
	struct dr_domain_rx_tx *nic_dmn = nic_matcher->nic_tbl->nic_dmn;
	uint32_t index;

	if (nic_matcher->fixed_size) {
		if (hw_ste) {
			index = dr_ste_calc_hash_index(hw_ste, nic_matcher->s_htbl);
			nic_rule->lock_index = index % NUM_OF_LOCKS;
		}
		pthread_spin_lock(&nic_dmn->locks[nic_rule->lock_index]);
	} else {
		pthread_spin_lock(&nic_dmn->locks[0]);
	}
}

static inline void
dr_rule_unlock(struct dr_rule_rx_tx *nic_rule)
{
	struct dr_matcher_rx_tx *nic_matcher = nic_rule->nic_matcher;
	struct dr_domain_rx_tx *nic_dmn = nic_matcher->nic_tbl->nic_dmn;

	if (nic_matcher->fixed_size)
		pthread_spin_unlock(&nic_dmn->locks[nic_rule->lock_index]);
	else
		pthread_spin_unlock(&nic_dmn->locks[0]);
}

void dr_rule_set_last_member(struct dr_rule_rx_tx *nic_rule,
			     struct dr_ste *ste,
			     bool force);

void dr_rule_get_reverse_rule_members(struct dr_ste **ste_arr,
				      struct dr_ste *curr_ste,
				      int *num_of_stes);

int dr_rule_send_update_list(struct list_head *send_ste_list,
			     struct mlx5dv_dr_domain *dmn,
			     bool is_reverse,
			     uint8_t send_ring_idx);

struct dr_icm_chunk {
	struct dr_icm_buddy_mem *buddy_mem;
	struct list_node	chunk_list;
	uint32_t		rkey;
	uint32_t		num_of_entries;
	uint32_t		byte_size;
	uint64_t		icm_addr;
	uint64_t		mr_addr;
	/* indicates the index of this chunk in the whole memory,
	 * used for deleting the chunk from the buddy
	 */
	uint32_t		seg;

	/* Memory optimisation */
	struct dr_ste		*ste_arr;
	uint8_t			*hw_ste_arr;
	struct list_head	*miss_list;
};

static inline int
dr_icm_pool_dm_type_to_entry_size(enum dr_icm_type icm_type)
{
	if (icm_type == DR_ICM_TYPE_STE)
		return DR_STE_SIZE;

	return DR_MODIFY_ACTION_SIZE;
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

	entry_size = dr_icm_pool_dm_type_to_entry_size(icm_type);

	num_of_entries = dr_icm_pool_chunk_size_to_entries(chunk_size);

	return entry_size * num_of_entries;
}

void dr_icm_pool_set_pool_max_log_chunk_sz(struct dr_icm_pool *pool,
					   enum dr_icm_chunk_size max_log_chunk_sz);

static inline int
dr_ste_htbl_increase_threshold(struct dr_ste_htbl *htbl)
{
	int num_of_entries =
		dr_icm_pool_chunk_size_to_entries(htbl->chunk_size);

	/* Threshold is 50%, one is added to table of size 1 */
	return (num_of_entries + 1) / 2;
}

static inline bool
dr_ste_htbl_may_grow(struct dr_ste_htbl *htbl)
{
	if (htbl->chunk_size == DR_CHUNK_SIZE_MAX - 1 ||
	    (htbl->type == DR_STE_HTBL_TYPE_LEGACY && !htbl->byte_mask))
		return false;

	return true;
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
struct mlx5dv_devx_obj *
dr_devx_create_flow_table(struct ibv_context *ctx,
			  struct dr_devx_flow_table_attr *table_attr);
int dr_devx_query_flow_table(struct mlx5dv_devx_obj *obj,  uint32_t type,
			     uint64_t *rx_icm_addr, uint64_t *tx_icm_addr);
struct dr_devx_tbl *
dr_devx_create_always_hit_ft(struct ibv_context *ctx,
			     struct dr_devx_flow_table_attr *ft_attr,
			     struct dr_devx_flow_group_attr *fg_attr,
			     struct dr_devx_flow_fte_attr *fte_attr);
void dr_devx_destroy_always_hit_ft(struct dr_devx_tbl *devx_tbl);
struct mlx5dv_devx_obj *
dr_devx_create_flow_sampler(struct ibv_context *ctx,
			    struct dr_devx_flow_sampler_attr *sampler_attr);
int dr_devx_query_flow_sampler(struct mlx5dv_devx_obj *obj,
			       uint64_t *rx_icm_addr, uint64_t *tx_icm_addr);
struct mlx5dv_devx_obj *dr_devx_create_definer(struct ibv_context *ctx,
					       uint16_t format_id,
					       uint8_t *match_mask);
struct mlx5dv_devx_obj *dr_devx_create_reformat_ctx(struct ibv_context *ctx,
						    enum reformat_type rt,
						    size_t reformat_size,
						    void *reformat_data);
struct mlx5dv_devx_obj
*dr_devx_create_meter(struct ibv_context *ctx,
		      struct mlx5dv_dr_flow_meter_attr *attr);
int dr_devx_query_meter(struct mlx5dv_devx_obj *obj, uint64_t *rx_icm_addr,
			uint64_t *tx_icm_addr);
int dr_devx_modify_meter(struct mlx5dv_devx_obj *obj,
			 struct mlx5dv_dr_flow_meter_attr *attr,
			 __be64 modify_bits);
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
	bool		isolate_vl_tc;
	uint8_t		qp_ts_format;
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
	uint32_t		qp_num;
	uint16_t		port_num;
	uint8_t			min_rnr_timer;
	uint8_t			sgid_index;
	bool			fl;
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

bool dr_domain_is_support_ste_icm_size(struct mlx5dv_dr_domain *dmn,
				       uint32_t req_log_icm_sz);
bool dr_domain_set_max_ste_icm_size(struct mlx5dv_dr_domain *dmn,
				    uint32_t req_log_icm_sz);
int dr_rule_rehash_matcher_s_anchor(struct mlx5dv_dr_matcher *matcher,
				    struct dr_matcher_rx_tx *nic_matcher,
				    enum dr_icm_chunk_size new_size);

struct dr_icm_pool *dr_icm_pool_create(struct mlx5dv_dr_domain *dmn,
				       enum dr_icm_type icm_type);
void dr_icm_pool_destroy(struct dr_icm_pool *pool);
int dr_icm_pool_sync_pool(struct dr_icm_pool *pool);

struct dr_icm_chunk *dr_icm_alloc_chunk(struct dr_icm_pool *pool,
					enum dr_icm_chunk_size chunk_size);
void dr_icm_free_chunk(struct dr_icm_chunk *chunk);
void dr_ste_prepare_for_postsend(struct dr_ste_ctx *ste_ctx,
				 uint8_t *hw_ste_p, uint32_t ste_size);
int dr_ste_htbl_init_and_postsend(struct mlx5dv_dr_domain *dmn,
				  struct dr_domain_rx_tx *nic_dmn,
				  struct dr_ste_htbl *htbl,
				  struct dr_htbl_connect_info *connect_info,
				  bool update_hw_ste,
				  uint8_t send_ring_idx);
void dr_ste_set_formated_ste(struct dr_ste_ctx *ste_ctx,
			     uint16_t gvmi,
			     enum dr_domain_nic_type nic_type,
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
	uint8_t nc_uar : 1;
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

struct dr_send_ring {
	struct dr_cq		cq;
	struct dr_qp		*qp;
	struct ibv_mr		*mr;
	/* How much wqes are waiting for completion */
	uint32_t		pending_wqe;
	/* Signal request per this trash hold value */
	uint16_t		signal_th;
	uint32_t                max_inline_size;
	/* manage the send queue */
	uint32_t		tx_head;
	/* protect QP/CQ operations */
	pthread_spinlock_t	lock;
	void			*buf;
	uint32_t		buf_size;
	void			*sync_buff;
	struct ibv_mr		*sync_mr;
};

int dr_send_ring_alloc(struct mlx5dv_dr_domain *dmn);
void dr_send_ring_free(struct mlx5dv_dr_domain *dmn);
int dr_send_ring_force_drain(struct mlx5dv_dr_domain *dmn);
bool dr_send_allow_fl(struct dr_devx_caps *caps);
int dr_send_postsend_ste(struct mlx5dv_dr_domain *dmn, struct dr_ste *ste,
			 uint8_t *data, uint16_t size, uint16_t offset,
			 uint8_t ring_idx);
int dr_send_postsend_htbl(struct mlx5dv_dr_domain *dmn, struct dr_ste_htbl *htbl,
			  uint8_t *formated_ste, uint8_t *mask,
			  uint8_t send_ring_idx);
int dr_send_postsend_formated_htbl(struct mlx5dv_dr_domain *dmn,
				   struct dr_ste_htbl *htbl,
				   uint8_t *ste_init_data,
				   bool update_hw_ste,
				   uint8_t send_ring_idx);
int dr_send_postsend_action(struct mlx5dv_dr_domain *dmn,
			    struct mlx5dv_dr_action *action);
/* buddy functions & structure */
struct dr_icm_mr;

struct dr_icm_buddy_mem {
	bitmap			**bits;
	unsigned int		*num_free;
	bitmap			**set_bit;
	uint32_t		max_order;
	struct list_node	list_node;
	struct dr_icm_mr	*icm_mr;
	struct dr_icm_pool	*pool;

	/* This is the list of used chunks. HW may be accessing this memory */
	struct list_head	used_list;
	size_t			used_memory;

	/* hardware may be accessing this memory but at some future,
	 * undetermined time, it might cease to do so.
	 * sync_ste command sets them free.
	 */
	struct list_head	hot_list;
	/* HW STE cache entry size */
	uint8_t                 hw_ste_sz;
};

int dr_buddy_init(struct dr_icm_buddy_mem *buddy, uint32_t max_order);
void dr_buddy_cleanup(struct dr_icm_buddy_mem *buddy);
int dr_buddy_alloc_mem(struct dr_icm_buddy_mem *buddy, int order);
void dr_buddy_free_mem(struct dr_icm_buddy_mem *buddy, uint32_t seg, int order);

void dr_vports_table_add_wire(struct dr_devx_vports *vports);
void dr_vports_table_del_wire(struct dr_devx_vports *vports);
struct dr_devx_vport_cap *dr_vports_table_get_vport_cap(struct dr_devx_caps *caps,
							uint16_t vport);
struct dr_devx_vport_cap *dr_vports_table_get_ib_port_cap(struct dr_devx_caps *caps,
							  uint32_t ib_port);
struct dr_vports_table *dr_vports_table_create(struct mlx5dv_dr_domain *dmn);
void dr_vports_table_destroy(struct dr_vports_table *vports_tbl);

#endif
