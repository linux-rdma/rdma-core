/*
 * Copyright (c) 2019 Mellanox Technologies, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
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
#include <inttypes.h>
#include "mlx5dv_dr.h"

#define BUFF_SIZE	1024

enum dr_dump_rec_type {
	DR_DUMP_REC_TYPE_DOMAIN = 3000,
	DR_DUMP_REC_TYPE_DOMAIN_INFO_FLEX_PARSER = 3001,
	DR_DUMP_REC_TYPE_DOMAIN_INFO_DEV_ATTR = 3002,
	DR_DUMP_REC_TYPE_DOMAIN_INFO_VPORT = 3003,
	DR_DUMP_REC_TYPE_DOMAIN_INFO_CAPS = 3004,
	DR_DUMP_REC_TYPE_DOMAIN_SEND_RING = 3005,

	DR_DUMP_REC_TYPE_TABLE = 3100,
	DR_DUMP_REC_TYPE_TABLE_RX = 3101,
	DR_DUMP_REC_TYPE_TABLE_TX = 3102,

	DR_DUMP_REC_TYPE_MATCHER = 3200,
	DR_DUMP_REC_TYPE_MATCHER_MASK = 3201,
	DR_DUMP_REC_TYPE_MATCHER_RX = 3202,
	DR_DUMP_REC_TYPE_MATCHER_TX = 3203,
	DR_DUMP_REC_TYPE_MATCHER_BUILDER = 3204,

	DR_DUMP_REC_TYPE_RULE = 3300,
	DR_DUMP_REC_TYPE_RULE_RX_ENTRY = 3301,
	DR_DUMP_REC_TYPE_RULE_TX_ENTRY = 3302,

	DR_DUMP_REC_TYPE_ACTION_ENCAP_L2 = 3400,
	DR_DUMP_REC_TYPE_ACTION_ENCAP_L3 = 3401,
	DR_DUMP_REC_TYPE_ACTION_MODIFY_HDR = 3402,
	DR_DUMP_REC_TYPE_ACTION_DROP = 3403,
	DR_DUMP_REC_TYPE_ACTION_QP = 3404,
	DR_DUMP_REC_TYPE_ACTION_FT = 3405,
	DR_DUMP_REC_TYPE_ACTION_CTR = 3406,
	DR_DUMP_REC_TYPE_ACTION_TAG = 3407,
	DR_DUMP_REC_TYPE_ACTION_VPORT = 3408,
	DR_DUMP_REC_TYPE_ACTION_DECAP_L2 = 3409,
	DR_DUMP_REC_TYPE_ACTION_DECAP_L3 = 3410,
};

static uint64_t dr_dump_icm_to_idx(uint64_t icm_addr)
{
	return (icm_addr >> 6) & 0xffffffff;
}

static void dump_hex_print(char *dest, char *src, uint32_t size)
{
	int i;

	for (i = 0; i < size; i++)
		sprintf(&dest[2 * i], "%02x", (uint8_t)src[i]);
}

static int dr_dump_rule_action_mem(FILE *f, const uint64_t rule_id,
				   struct dr_rule_action_member *action_mem)
{
	struct mlx5dv_dr_action *action = action_mem->action;
	const uint64_t action_id = (uint64_t)action;
	int ret;

	switch (action->action_type) {
	case DR_ACTION_TYP_DROP:
		ret = fprintf(f, "%d,0x%" PRIx64 ",0x%" PRIx64 "\n",
			      DR_DUMP_REC_TYPE_ACTION_DROP, action_id, rule_id);
		break;
	case DR_ACTION_TYP_FT:
		ret = fprintf(f, "%d,0x%" PRIx64 ",0x%" PRIx64 ",0x%x\n",
			      DR_DUMP_REC_TYPE_ACTION_FT, action_id, rule_id,
			      action->dest_tbl->devx_obj->object_id);
		break;
	case DR_ACTION_TYP_QP:
		ret = fprintf(f, "%d,0x%" PRIx64 ",0x%" PRIx64 ",0x%x\n",
			      DR_DUMP_REC_TYPE_ACTION_QP, action_id, rule_id,
			      action->qp->qp_num);
		break;
	case DR_ACTION_TYP_CTR:
		ret = fprintf(f, "%d,0x%" PRIx64 ",0x%" PRIx64 ",0x%x\n",
			      DR_DUMP_REC_TYPE_ACTION_CTR, action_id, rule_id,
			      action->ctr.devx_obj->object_id +
			      action->ctr.offset);
		break;
	case DR_ACTION_TYP_TAG:
		ret = fprintf(f, "%d,,0x%" PRIx64 ",0x%" PRIx64 "0x%x\n",
			      DR_DUMP_REC_TYPE_ACTION_TAG, action_id, rule_id,
			      action->flow_tag);
		break;
	case DR_ACTION_TYP_MODIFY_HDR:
		ret = fprintf(f, "%d,,0x%" PRIx64 ",0x%" PRIx64 "0x%x\n",
			      DR_DUMP_REC_TYPE_ACTION_MODIFY_HDR, action_id,
			      rule_id, action->rewrite.index);
		break;
	case DR_ACTION_TYP_VPORT:
		ret = fprintf(f, "%d,0x%" PRIx64 ",0x%" PRIx64 ",0x%x\n",
			      DR_DUMP_REC_TYPE_ACTION_VPORT, action_id, rule_id,
			      action->vport.num);
		break;
	case DR_ACTION_TYP_TNL_L2_TO_L2:
		ret = fprintf(f, "%d,0x%" PRIx64 ",0x%" PRIx64 "\n",
			      DR_DUMP_REC_TYPE_ACTION_DECAP_L2, action_id,
			      rule_id);
		break;
	case DR_ACTION_TYP_TNL_L3_TO_L2:
		ret = fprintf(f, "%d,0x%" PRIx64 ",0x%" PRIx64 ",0x%x\n",
			      DR_DUMP_REC_TYPE_ACTION_DECAP_L3, action_id,
			      rule_id, action->rewrite.index);
		break;
	case DR_ACTION_TYP_L2_TO_TNL_L2:
		ret = fprintf(f, "%d,0x%" PRIx64 ",0x%" PRIx64 ",0x%x\n",
			      DR_DUMP_REC_TYPE_ACTION_ENCAP_L2, action_id,
			      rule_id, action->reformat.dvo->object_id);
		break;
	case DR_ACTION_TYP_L2_TO_TNL_L3:
		ret = fprintf(f, "%d,0x%" PRIx64 ",0x%" PRIx64 ",0x%x\n",
			      DR_DUMP_REC_TYPE_ACTION_ENCAP_L3, action_id,
			      rule_id, action->reformat.dvo->object_id);
		break;
	default:
		return 0;
	}

	if (ret < 0)
		return ret;

	return 0;
}

static int dr_dump_rule_mem(FILE *f, struct dr_rule_member *rule_mem,
			    bool is_rx, const uint64_t rule_id)
{
	char hw_ste_dump[BUFF_SIZE] = {};
	enum dr_dump_rec_type mem_rec_type;
	int ret;

	mem_rec_type = is_rx ? DR_DUMP_REC_TYPE_RULE_RX_ENTRY :
			       DR_DUMP_REC_TYPE_RULE_TX_ENTRY;

	dump_hex_print(hw_ste_dump, (char *)rule_mem->ste->hw_ste, DR_STE_SIZE_REDUCED);
	ret = fprintf(f, "%d,0x%" PRIx64 ",0x%" PRIx64 ",%s\n",
		      mem_rec_type,
		      dr_dump_icm_to_idx(dr_ste_get_icm_addr(rule_mem->ste)),
		      rule_id,
		      hw_ste_dump);
	if (ret < 0)
		return ret;

	return 0;
}

static int dr_dump_rule_rx_tx(FILE *f, struct dr_rule_rx_tx *rule_rx_tx,
			      bool is_rx, const uint64_t rule_id)
{
	struct dr_rule_member *rule_mem;
	int ret;

	list_for_each(&rule_rx_tx->rule_members_list, rule_mem, list) {
		ret = dr_dump_rule_mem(f, rule_mem, is_rx, rule_id);
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int dr_dump_rule(FILE *f, struct mlx5dv_dr_rule *rule)
{
	struct dr_rule_action_member *action_mem;
	const uint64_t rule_id = (uint64_t)rule;
	struct dr_rule_rx_tx *rx = &rule->rx;
	struct dr_rule_rx_tx *tx = &rule->tx;
	int ret;

	ret = fprintf(f, "%d,0x%" PRIx64 ",0x%" PRIx64 "\n",
		      DR_DUMP_REC_TYPE_RULE,
		      rule_id,
		      (uint64_t)rule->matcher);
	if (ret < 0)
		return ret;

	if (!dr_is_root_table(rule->matcher->tbl)) {
		if (rx->nic_matcher) {
			ret = dr_dump_rule_rx_tx(f, rx, true, rule_id);
			if (ret < 0)
				return ret;
		}

		if (tx->nic_matcher) {
			ret = dr_dump_rule_rx_tx(f, tx, false, rule_id);
			if (ret < 0)
				return ret;
		}
	}

	list_for_each(&rule->rule_actions_list, action_mem, list) {
		ret = dr_dump_rule_action_mem(f, rule_id, action_mem);
		if (ret < 0)
			return ret;
	}

	return 0;
}

int mlx5dv_dump_dr_rule(FILE *fout, struct mlx5dv_dr_rule *rule)
{
	int ret;

	if (!fout || !rule)
		return -EINVAL;

	pthread_mutex_lock(&rule->matcher->tbl->dmn->mutex);

	ret = dr_dump_rule(fout, rule);

	pthread_mutex_unlock(&rule->matcher->tbl->dmn->mutex);

	return ret;
}

static int dr_dump_matcher_mask(FILE *f, struct dr_match_param *mask,
				 uint8_t criteria, const uint64_t matcher_id)
{
	char dump[BUFF_SIZE] = {};
	int ret;

	ret = fprintf(f, "%d,0x%" PRIx64 ",", DR_DUMP_REC_TYPE_MATCHER_MASK, matcher_id);
	if (ret < 0)
		return ret;

	if (criteria & DR_MATCHER_CRITERIA_OUTER) {
		dump_hex_print(dump, (char *)&mask->outer, sizeof(mask->outer));
		ret = fprintf(f, "%s,", dump);
	} else {
		ret = fprintf(f, ",");
	}

	if (ret < 0)
		return ret;

	if (criteria & DR_MATCHER_CRITERIA_INNER) {
		dump_hex_print(dump, (char *)&mask->inner, sizeof(mask->inner));
		ret = fprintf(f, "%s,", dump);
	} else {
		ret = fprintf(f, ",");
	}


	if (ret < 0)
		return ret;

	if (criteria & DR_MATCHER_CRITERIA_MISC) {
		dump_hex_print(dump, (char *)&mask->misc, sizeof(mask->misc));
		ret = fprintf(f, "%s,", dump);
	} else {
		ret = fprintf(f, ",");
	}

	if (ret < 0)
		return ret;

	if (criteria & DR_MATCHER_CRITERIA_MISC2) {
		dump_hex_print(dump, (char *)&mask->misc2, sizeof(mask->misc2));
		ret = fprintf(f, "%s,", dump);
	} else {
		ret = fprintf(f, ",");
	}

	if (ret < 0)
		return ret;

	if (criteria & DR_MATCHER_CRITERIA_MISC3) {
		dump_hex_print(dump, (char *)&mask->misc3, sizeof(mask->misc3));
		ret = fprintf(f, "%s\n", dump);
	} else {
		ret = fprintf(f, ",\n");
	}

	if (ret < 0)
		return ret;

	return 0;
}

static int dr_dump_matcher_builder(FILE *f, struct dr_ste_build *builder,
				   uint32_t index, bool is_rx,
				   const uint64_t matcher_id)
{
	int ret;

	ret = fprintf(f, "%d,0x%" PRIx64 "%d,%d,0x%x\n",
		      DR_DUMP_REC_TYPE_MATCHER_BUILDER,
		      matcher_id,
		      index,
		      is_rx,
		      builder->lu_type);
	if (ret < 0)
		return ret;

	return 0;
}

static int dr_dump_matcher_rx_tx(FILE *f, bool is_rx,
				 struct dr_matcher_rx_tx *matcher_rx_tx,
				 const uint64_t matcher_id)
{
	enum dr_dump_rec_type rec_type;
	int i, ret;

	rec_type = is_rx ? DR_DUMP_REC_TYPE_MATCHER_RX :
			   DR_DUMP_REC_TYPE_MATCHER_TX;

	ret = fprintf(f, "%d,0x%" PRIx64 ",0x%" PRIx64 ",%d,0x%" PRIx64 ",0x%" PRIx64 "\n",
		      rec_type,
		      (uint64_t)matcher_rx_tx,
		      matcher_id,
		      matcher_rx_tx->num_of_builders,
		      dr_dump_icm_to_idx(matcher_rx_tx->s_htbl->chunk->icm_addr),
		      dr_dump_icm_to_idx(matcher_rx_tx->e_anchor->chunk->icm_addr));
	if (ret < 0)
		return ret;

	for (i = 0; i < matcher_rx_tx->num_of_builders; i++) {
		ret = dr_dump_matcher_builder(f, &matcher_rx_tx->ste_builder[i],
					      i, is_rx, matcher_id);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int dr_dump_matcher(FILE *f, struct mlx5dv_dr_matcher *matcher)
{
	struct dr_matcher_rx_tx *rx = &matcher->rx;
	struct dr_matcher_rx_tx *tx = &matcher->tx;
	uint64_t matcher_id;
	int ret;

	matcher_id = (uint64_t)matcher;

	ret = fprintf(f, "%d,0x%" PRIx64 ",0x%" PRIx64 ",%d\n",
		      DR_DUMP_REC_TYPE_MATCHER,
		      matcher_id,
		      (uint64_t)matcher->tbl,
		      matcher->prio);
	if (ret < 0)
		return ret;


	if (!dr_is_root_table(matcher->tbl)) {
		ret = dr_dump_matcher_mask(f, &matcher->mask, matcher->match_criteria, matcher_id);
		if (ret < 0)
			return ret;

		if (rx->nic_tbl) {
			ret = dr_dump_matcher_rx_tx(f, true, rx, matcher_id);
			if (ret < 0)
				return ret;
		}

		if (tx->nic_tbl) {
			ret = dr_dump_matcher_rx_tx(f, false, tx, matcher_id);
			if (ret < 0)
				return ret;
		}
	}

	return 0;
}

static int dr_dump_matcher_all(FILE *fout, struct mlx5dv_dr_matcher *matcher)
{
	struct mlx5dv_dr_rule *rule;
	int ret;

	ret = dr_dump_matcher(fout, matcher);
	if (ret < 0)
		return ret;

	list_for_each(&matcher->rule_list, rule, rule_list) {
		ret = dr_dump_rule(fout, rule);
		if (ret < 0)
			return ret;
	}

	return 0;
}

int mlx5dv_dump_dr_matcher(FILE *fout, struct mlx5dv_dr_matcher *matcher)
{
	int ret;

	if (!fout || !matcher)
		return -EINVAL;

	pthread_mutex_lock(&matcher->tbl->dmn->mutex);

	ret = dr_dump_matcher_all(fout, matcher);

	pthread_mutex_unlock(&matcher->tbl->dmn->mutex);

	return ret;
}

static uint64_t dr_domain_id_calc(enum mlx5dv_dr_domain_type type)
{
	return (getpid() << 8) | (type & 0xff);
}

static int dr_dump_table_rx_tx(FILE *f, bool is_rx,
			       struct dr_table_rx_tx *table_rx_tx,
			       const uint64_t table_id)
{
	enum dr_dump_rec_type rec_type;
	int ret;

	rec_type = is_rx ? DR_DUMP_REC_TYPE_TABLE_RX : DR_DUMP_REC_TYPE_TABLE_TX;

	ret = fprintf(f, "%d,0x%" PRIx64 ",0x%" PRIx64 "\n",
		      rec_type,
		      table_id,
		      dr_dump_icm_to_idx(table_rx_tx->s_anchor->chunk->icm_addr));
	if (ret < 0)
		return ret;

	return 0;
}

static int dr_dump_table(FILE *f, struct mlx5dv_dr_table *table)
{
	struct dr_table_rx_tx *rx = &table->rx;
	struct dr_table_rx_tx *tx = &table->tx;
	int ret;

	ret = fprintf(f, "%d,0x%" PRIx64 ",0x%" PRIx64 ",%d,%d\n",
		      DR_DUMP_REC_TYPE_TABLE,
		      (uint64_t) table,
		      dr_domain_id_calc(table->dmn->type),
		      table->table_type,
		      table->level);
	if (ret < 0)
		return ret;

	if (!dr_is_root_table(table)) {
		if (rx->nic_dmn) {
			ret = dr_dump_table_rx_tx(f, true, rx, (uint64_t)table);
			if (ret < 0)
				return ret;
		}

		if (tx->nic_dmn) {
			ret = dr_dump_table_rx_tx(f, false, tx, (uint64_t)table);
			if (ret < 0)
				return ret;
		}
	}
	return 0;
}

static int dr_dump_table_all(FILE *fout, struct mlx5dv_dr_table *tbl)
{
	struct mlx5dv_dr_matcher *matcher;
	int ret;

	ret = dr_dump_table(fout, tbl);
	if (ret < 0)
		return ret;

	if (!dr_is_root_table(tbl)) {
		list_for_each(&tbl->matcher_list, matcher, matcher_list) {
			ret = dr_dump_matcher_all(fout, matcher);
			if (ret < 0)
				return ret;
		}
	}
	return 0;
}

int mlx5dv_dump_dr_table(FILE *fout, struct mlx5dv_dr_table *tbl)
{
	int ret;

	if (!fout || !tbl)
		return -EINVAL;

	pthread_mutex_lock(&tbl->dmn->mutex);

	ret = dr_dump_table_all(fout, tbl);

	pthread_mutex_unlock(&tbl->dmn->mutex);

	return ret;
}

static int dr_dump_send_ring(FILE *f, struct dr_send_ring *ring,
			     const uint64_t domain_id)
{
	int ret;

	ret = fprintf(f, "%d,0x%" PRIx64 ",0x%" PRIx64 ",0x%x,0x%x\n",
		      DR_DUMP_REC_TYPE_DOMAIN_SEND_RING,
		      (uint64_t)ring,
		      domain_id,
		      ring->cq.cqn,
		      ring->qp->obj->object_id);
	if (ret < 0)
		return ret;

	return 0;
}

static int dr_dump_domain_info_flex_parser(FILE *f, const char *flex_parser_name,
					   const uint8_t flex_parser_value,
					   const uint64_t domain_id)
{
	int ret;

	ret = fprintf(f, "%d,0x%" PRIx64 ",%s,0x%x\n",
		      DR_DUMP_REC_TYPE_DOMAIN_INFO_FLEX_PARSER,
		      domain_id,
		      flex_parser_name,
		      flex_parser_value);
	if (ret < 0)
		return ret;

	return 0;
}

static int dr_dump_domain_info_caps(FILE *f, struct dr_devx_caps *caps,
					 const uint64_t domain_id)
{
	int i, ret;

	ret = fprintf(f, "%d,0x%" PRIx64 ",0x%x,0x%" PRIx64 ",0x%" PRIx64 ",0x%x,%d,%d\n",
		      DR_DUMP_REC_TYPE_DOMAIN_INFO_CAPS,
		      domain_id,
		      caps->gvmi,
		      caps->nic_rx_drop_address,
		      caps->nic_tx_drop_address,
		      caps->flex_protocols,
		      caps->num_vports,
		      caps->eswitch_manager);
	if (ret < 0)
		return ret;

	for (i = 0; i < caps->num_vports; i++) {
		ret = fprintf(f, "%d,0x%" PRIx64 ",%d,0x%x,0x%" PRIx64 ",0x%" PRIx64 "\n",
			      DR_DUMP_REC_TYPE_DOMAIN_INFO_VPORT,
			      domain_id,
			      i,
			      caps->vports_caps[i].gvmi,
			      caps->vports_caps[i].icm_address_rx,
			      caps->vports_caps[i].icm_address_tx);
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int dr_dump_domain_info_dev_attr(FILE *f, struct ibv_device_attr *attr,
					const uint64_t domain_id)
{
	int ret;

	ret = fprintf(f, "%d,0x%" PRIx64 ",%d,%s\n",
		      DR_DUMP_REC_TYPE_DOMAIN_INFO_DEV_ATTR,
		      domain_id,
		      attr->phys_port_cnt,
		      attr->fw_ver);
	if (ret < 0)
		return ret;

	return 0;
}
static int dr_dump_domain_info(FILE *f, struct dr_domain_info *info,
			       const uint64_t domain_id)
{
	int ret;

	ret = dr_dump_domain_info_dev_attr(f, &info->attr, domain_id);
	if (ret < 0)
		return ret;

	ret = dr_dump_domain_info_caps(f, &info->caps, domain_id);
	if (ret < 0)
		return ret;

	ret = dr_dump_domain_info_flex_parser(f, "icmp_dw0", info->caps.flex_parser_id_icmp_dw0, domain_id);
	if (ret < 0)
		return ret;

	ret = dr_dump_domain_info_flex_parser(f, "icmp_dw1", info->caps.flex_parser_id_icmp_dw1, domain_id);
	if (ret < 0)
		return ret;

	ret = dr_dump_domain_info_flex_parser(f, "icmpv6_dw0", info->caps.flex_parser_id_icmpv6_dw0, domain_id);
	if (ret < 0)
		return ret;

	ret = dr_dump_domain_info_flex_parser(f, "icmpv6_dw1", info->caps.flex_parser_id_icmpv6_dw1, domain_id);
	if (ret < 0)
		return ret;

	return 0;
}

static int dr_dump_domain(FILE *f, struct mlx5dv_dr_domain *dmn)
{
	enum mlx5dv_dr_domain_type dmn_type = dmn->type;
	char *dev_name = dmn->ctx->device->dev_name;
	uint64_t domain_id;
	int ret;

	domain_id = dr_domain_id_calc(dmn_type);

	ret = fprintf(f, "%d,0x%" PRIx64 ",%d,0%x,%d,%s,%s\n",
		      DR_DUMP_REC_TYPE_DOMAIN,
		      domain_id,
		      dmn_type,
		      dmn->info.caps.gvmi,
		      dmn->info.supp_sw_steering,
		      PACKAGE_VERSION,
		      dev_name);
	if (ret < 0)
		return ret;

	ret = dr_dump_domain_info(f, &dmn->info, domain_id);
	if (ret < 0)
		return ret;

	if (dmn->info.supp_sw_steering) {
		ret = dr_dump_send_ring(f, dmn->send_ring, domain_id);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int dr_dump_domain_all(FILE *fout, struct mlx5dv_dr_domain *dmn)
{
	struct mlx5dv_dr_table *tbl;
	int ret;

	ret = dr_dump_domain(fout, dmn);
	if (ret < 0)
		return ret;

	list_for_each(&dmn->tbl_list, tbl, tbl_list) {
		ret = dr_dump_table_all(fout, tbl);
		if (ret < 0)
			return ret;
	}

	return 0;
}

int mlx5dv_dump_dr_domain(FILE *fout, struct mlx5dv_dr_domain *dmn)
{
	int ret;

	if (!fout || !dmn)
		return -EINVAL;

	pthread_mutex_lock(&dmn->mutex);

	ret = dr_dump_domain_all(fout, dmn);

	pthread_mutex_unlock(&dmn->mutex);

	return ret;
}

