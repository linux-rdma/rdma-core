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
