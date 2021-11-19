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
#include <ccan/ilog.h>
#include "mlx5dv_dr.h"
#include "dr_ste.h"

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
	DR_ACTION_STATE_ENCAP,
	DR_ACTION_STATE_DECAP,
	DR_ACTION_STATE_MODIFY_HDR,
	DR_ACTION_STATE_POP_VLAN,
	DR_ACTION_STATE_PUSH_VLAN,
	DR_ACTION_STATE_NON_TERM,
	DR_ACTION_STATE_TERM,
	DR_ACTION_STATE_ASO,
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
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]	= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_TNL_L2_TO_L2]	= DR_ACTION_STATE_DECAP,
			[DR_ACTION_TYP_TNL_L3_TO_L2]	= DR_ACTION_STATE_DECAP,
			[DR_ACTION_TYP_L2_TO_TNL_L2]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_POP_VLAN]	= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_PUSH_VLAN]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_ASO_FLOW_METER]	= DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_CT]		= DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_MISS]		= DR_ACTION_STATE_TERM,
		},
		[DR_ACTION_STATE_DECAP] = {
			[DR_ACTION_TYP_QP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_TAG]		= DR_ACTION_STATE_DECAP,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_DECAP,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_DECAP,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]	= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_POP_VLAN]	= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_PUSH_VLAN]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_ASO_FLOW_METER]  = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_CT]		= DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_L2_TO_TNL_L2]    = DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]    = DR_ACTION_STATE_ENCAP,
		},
		[DR_ACTION_STATE_MODIFY_HDR] = {
			[DR_ACTION_TYP_QP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_TAG]		= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]	= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_ASO_FLOW_METER]  = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_PUSH_VLAN]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_ASO_CT]		= DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_L2_TO_TNL_L2]    = DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]    = DR_ACTION_STATE_ENCAP,
		},
		[DR_ACTION_STATE_POP_VLAN] = {
			[DR_ACTION_TYP_QP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_TAG]		= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_POP_VLAN]	= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]	= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_ASO_FLOW_METER]  = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_CT]		= DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_L2_TO_TNL_L2]    = DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]    = DR_ACTION_STATE_ENCAP,
		},
		[DR_ACTION_STATE_PUSH_VLAN] = {
			[DR_ACTION_TYP_QP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_TAG]		= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_PUSH_VLAN]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]	= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_L2_TO_TNL_L2]    = DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]    = DR_ACTION_STATE_ENCAP,
		},
		[DR_ACTION_STATE_NON_TERM] = {
			[DR_ACTION_TYP_DROP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_QP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_TAG]		= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]	= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_TNL_L2_TO_L2]	= DR_ACTION_STATE_DECAP,
			[DR_ACTION_TYP_TNL_L3_TO_L2]	= DR_ACTION_STATE_DECAP,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_POP_VLAN]	= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_PUSH_VLAN]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_MISS]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_ASO_FLOW_METER]  = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_CT]		= DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_L2_TO_TNL_L2]    = DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]    = DR_ACTION_STATE_ENCAP,
		},
		[DR_ACTION_STATE_ASO] = {
			[DR_ACTION_TYP_QP]              = DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]              = DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]         = DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]      = DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]             = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_FIRST_HIT]   = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_FLOW_METER]  = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_CT]          = DR_ACTION_STATE_ASO,
		},
		[DR_ACTION_STATE_ENCAP] = {
			[DR_ACTION_TYP_QP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]	= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_TAG]		= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_ASO,
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
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_L2_TO_TNL_L2]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_PUSH_VLAN]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_POP_VLAN]	= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_ASO_FLOW_METER]  = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_CT]		= DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_MISS]		= DR_ACTION_STATE_TERM,
		},
		[DR_ACTION_STATE_ENCAP] = {
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
		},
		[DR_ACTION_STATE_MODIFY_HDR] = {
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_L2_TO_TNL_L2]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_PUSH_VLAN]	= DR_ACTION_STATE_PUSH_VLAN,
		},
		[DR_ACTION_STATE_POP_VLAN] = {
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_POP_VLAN]	= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_PUSH_VLAN]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_L2_TO_TNL_L2]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]	= DR_ACTION_STATE_ENCAP,
		},
		[DR_ACTION_STATE_PUSH_VLAN] = {
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_PUSH_VLAN]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_L2_TO_TNL_L2]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]	= DR_ACTION_STATE_ENCAP,
		},
		[DR_ACTION_STATE_NON_TERM] = {
			[DR_ACTION_TYP_DROP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_L2_TO_TNL_L2]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_PUSH_VLAN]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_POP_VLAN]	= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_MISS]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_ASO_FLOW_METER]  = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_CT]		= DR_ACTION_STATE_ASO,
		},
		[DR_ACTION_STATE_ASO] = {
			[DR_ACTION_TYP_L2_TO_TNL_L2]    = DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]    = DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_MODIFY_HDR]      = DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_PUSH_VLAN]       = DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_CTR]             = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_FIRST_HIT]   = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_FLOW_METER]  = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_CT]          = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_DROP]            = DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]              = DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_MISS]            = DR_ACTION_STATE_TERM,
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
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]	= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_TNL_L2_TO_L2]	= DR_ACTION_STATE_DECAP,
			[DR_ACTION_TYP_TNL_L3_TO_L2]	= DR_ACTION_STATE_DECAP,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_POP_VLAN]	= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_PUSH_VLAN]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_VPORT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_ASO_FLOW_METER]  = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_CT]		= DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_MISS]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_L2_TO_TNL_L2]    = DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]    = DR_ACTION_STATE_ENCAP,
		},
		[DR_ACTION_STATE_DECAP] = {
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_DECAP,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_DECAP,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]	= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_POP_VLAN]	= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_PUSH_VLAN]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_VPORT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_ASO_FLOW_METER]  = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_CT]		= DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_L2_TO_TNL_L2]    = DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]    = DR_ACTION_STATE_ENCAP,
		},
		[DR_ACTION_STATE_ENCAP] = {
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]	= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_VPORT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_ASO,
		},
		[DR_ACTION_STATE_MODIFY_HDR] = {
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]	= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_VPORT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_ASO_FLOW_METER]  = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_PUSH_VLAN]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_ASO_CT]		= DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_L2_TO_TNL_L2]    = DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]    = DR_ACTION_STATE_ENCAP,
		},
		[DR_ACTION_STATE_POP_VLAN] = {
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_POP_VLAN]	= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_VPORT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]	= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_ASO_FLOW_METER]  = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_CT]		= DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_L2_TO_TNL_L2]    = DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]    = DR_ACTION_STATE_ENCAP,
		},
		[DR_ACTION_STATE_PUSH_VLAN] = {
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_PUSH_VLAN]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_VPORT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]	= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_ASO_FLOW_METER]  = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_L2_TO_TNL_L2]    = DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]    = DR_ACTION_STATE_ENCAP,
		},
		[DR_ACTION_STATE_NON_TERM] = {
			[DR_ACTION_TYP_DROP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]	= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_TNL_L2_TO_L2]	= DR_ACTION_STATE_DECAP,
			[DR_ACTION_TYP_TNL_L3_TO_L2]	= DR_ACTION_STATE_DECAP,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_POP_VLAN]	= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_PUSH_VLAN]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_VPORT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_MISS]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_ASO_FLOW_METER]  = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_CT]		= DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_L2_TO_TNL_L2]    = DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]    = DR_ACTION_STATE_ENCAP,
		},
		[DR_ACTION_STATE_ASO] = {
			[DR_ACTION_TYP_VPORT]           = DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]              = DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]         = DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]      = DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]             = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_FIRST_HIT]   = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_FLOW_METER]  = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_CT]          = DR_ACTION_STATE_ASO,
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
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]	= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_L2_TO_TNL_L2]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_PUSH_VLAN]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_POP_VLAN]	= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_VPORT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_ASO_FLOW_METER]  = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_CT]		= DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_MISS]		= DR_ACTION_STATE_TERM,
		},
		[DR_ACTION_STATE_ENCAP] = {
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]	= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_VPORT]		= DR_ACTION_STATE_TERM,
		},
		[DR_ACTION_STATE_MODIFY_HDR] = {
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]	= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_L2_TO_TNL_L2]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_PUSH_VLAN]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_VPORT]		= DR_ACTION_STATE_TERM,
		},
		[DR_ACTION_STATE_POP_VLAN] = {
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_POP_VLAN]	= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_PUSH_VLAN]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_L2_TO_TNL_L2]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_SAMPLER]         = DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]      = DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_VPORT]           = DR_ACTION_STATE_TERM,
		},
		[DR_ACTION_STATE_PUSH_VLAN] = {
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_PUSH_VLAN]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_L2_TO_TNL_L2]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]	= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_VPORT]		= DR_ACTION_STATE_TERM,
		},
		[DR_ACTION_STATE_NON_TERM] = {
			[DR_ACTION_TYP_DROP]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_ASO_FIRST_HIT]	= DR_ACTION_STATE_NON_TERM,
			[DR_ACTION_TYP_MODIFY_HDR]	= DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_METER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]	= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_L2_TO_TNL_L2]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]	= DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_PUSH_VLAN]	= DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_POP_VLAN]	= DR_ACTION_STATE_POP_VLAN,
			[DR_ACTION_TYP_VPORT]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_MISS]		= DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_ASO_FLOW_METER]  = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_CT]          = DR_ACTION_STATE_ASO,
		},
		[DR_ACTION_STATE_ASO] = {
			[DR_ACTION_TYP_L2_TO_TNL_L2]    = DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_L2_TO_TNL_L3]    = DR_ACTION_STATE_ENCAP,
			[DR_ACTION_TYP_MODIFY_HDR]      = DR_ACTION_STATE_MODIFY_HDR,
			[DR_ACTION_TYP_PUSH_VLAN]       = DR_ACTION_STATE_PUSH_VLAN,
			[DR_ACTION_TYP_VPORT]           = DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_FT]              = DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_SAMPLER]         = DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_DEST_ARRAY]      = DR_ACTION_STATE_TERM,
			[DR_ACTION_TYP_CTR]             = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_FIRST_HIT]   = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_FLOW_METER]  = DR_ACTION_STATE_ASO,
			[DR_ACTION_TYP_ASO_CT]          = DR_ACTION_STATE_ASO,
		},
		[DR_ACTION_STATE_TERM] = {
			[DR_ACTION_TYP_CTR]		= DR_ACTION_STATE_TERM,
		},
	},
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

/* Apply the actions on the rule STE array starting from the last_ste.
 * Actions might require more than one STE, new_num_stes will return
 * the new size of the STEs array, rule with actions. */
static void dr_actions_apply(struct mlx5dv_dr_domain *dmn,
			     enum dr_domain_nic_type nic_type,
			     uint8_t *action_type_set,
			     uint8_t *last_ste,
			     struct dr_ste_actions_attr *attr,
			     uint32_t *new_num_stes)
{
	struct dr_ste_ctx *ste_ctx = dmn->ste_ctx;
	uint32_t added_stes = 0;

	if (nic_type == DR_DOMAIN_NIC_TYPE_RX)
		dr_ste_set_actions_rx(ste_ctx, action_type_set,
				      last_ste, attr, &added_stes);
	else
		dr_ste_set_actions_tx(ste_ctx, action_type_set,
				      last_ste, attr, &added_stes);

	*new_num_stes += added_stes;
}

static enum dr_action_domain
dr_action_get_action_domain(enum mlx5dv_dr_domain_type domain,
			    enum dr_domain_nic_type nic_type)
{
	if (domain == MLX5DV_DR_DOMAIN_TYPE_NIC_RX) {
		return DR_ACTION_DOMAIN_NIC_INGRESS;
	} else if (domain == MLX5DV_DR_DOMAIN_TYPE_NIC_TX) {
		return DR_ACTION_DOMAIN_NIC_EGRESS;
	} else {
		/* FDB domain */
		if (nic_type == DR_DOMAIN_NIC_TYPE_RX)
			return DR_ACTION_DOMAIN_FDB_INGRESS;
		else
			return DR_ACTION_DOMAIN_FDB_EGRESS;
	}
}

static int
dr_action_validate_and_get_next_state(enum dr_action_domain action_domain,
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
			     uint32_t *new_hw_ste_arr_sz,
			     struct cross_dmn_params *cross_dmn_p)
{
	struct dr_domain_rx_tx *nic_dmn = nic_matcher->nic_tbl->nic_dmn;
	bool rx_rule = nic_dmn->type == DR_DOMAIN_NIC_TYPE_RX;
	struct mlx5dv_dr_action *cross_dmn_action = NULL;
	struct mlx5dv_dr_domain *dmn = matcher->tbl->dmn;
	uint8_t action_type_set[DR_ACTION_TYP_MAX] = {};
	uint32_t state = DR_ACTION_STATE_NO_ACTION;
	struct dr_ste_actions_attr attr = {};
	enum dr_action_domain action_domain;
	uint8_t *last_ste;
	int i;

	attr.gvmi = dmn->info.caps.gvmi;
	attr.hit_gvmi = dmn->info.caps.gvmi;
	attr.final_icm_addr = nic_dmn->default_icm_addr;
	action_domain = dr_action_get_action_domain(dmn->type, nic_dmn->type);
	attr.aso_ste_loc = -1;

	for (i = 0; i < num_actions; i++) {
		struct mlx5dv_dr_action *action;
		int max_actions_type = 1;
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
			if (action->dest_qp.is_qp)
				attr.final_icm_addr = to_mqp(action->dest_qp.qp)->tir_icm_addr;
			else
				attr.final_icm_addr = action->dest_qp.devx_tir->rx_icm_addr;

			if (!attr.final_icm_addr) {
				dr_dbg(dmn, "Unsupported TIR/QP for action\n");
				goto out_invalid_arg;
			}
			break;
		case DR_ACTION_TYP_CTR:
			attr.ctr_id = action->ctr.devx_obj->object_id +
				action->ctr.offset;
			break;
		case DR_ACTION_TYP_ASO_CT:
			if (dmn != action->aso.dmn) {
				if (!action->aso.devx_obj->priv) {
					dr_dbg(dmn, "ASO CT devx priv object is not initialized\n");
					goto out_invalid_arg;
				}

				struct dr_aso_cross_dmn_arrays *cross_dmn_arrays =
					(struct dr_aso_cross_dmn_arrays *) action->aso.devx_obj->priv;

				if (atomic_fetch_add(&cross_dmn_arrays->rule_htbl[action->aso.offset]->ste_arr->refcount, 1) > 1) {
					dr_dbg(dmn, "ASO CT cross GVMI action is in use by another rule\n");
					atomic_fetch_sub(&cross_dmn_arrays->rule_htbl[action->aso.offset]->ste_arr->refcount, 1);
					errno = EBUSY;
					goto out_errno;
				}

				dr_ste_get(cross_dmn_arrays->action_htbl[action->aso.offset]->ste_arr);
				cross_dmn_p->cross_dmn_action = action;
				cross_dmn_action = action;
			}

			attr.aso = &action->aso;
			break;
		case DR_ACTION_TYP_ASO_FLOW_METER:
		case DR_ACTION_TYP_ASO_FIRST_HIT:
			if (dmn->ctx != action->aso.devx_obj->context) {
				dr_dbg(dmn, "ASO belongs to a different IB ctx\n");
				goto out_invalid_arg;
			}
			attr.aso = &action->aso;
			break;
		case DR_ACTION_TYP_TAG:
			attr.flow_tag = action->flow_tag;
			break;
		case DR_ACTION_TYP_MISS:
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
			if (rx_rule &&
			    !(dmn->ste_ctx->actions_caps & DR_STE_CTX_ACTION_CAP_RX_ENCAP)) {
				dr_dbg(dmn, "Device doesn't support Encap on RX\n");
				goto out_invalid_arg;
			}

			attr.reformat_size = action->reformat.reformat_size;
			attr.reformat_id = action->reformat.dvo->object_id;
			attr.prio_tag_required = dmn->info.caps.prio_tag_required;
			break;
		case DR_ACTION_TYP_METER:
			if (action->meter.next_ft->dmn != dmn) {
				dr_dbg(dmn, "Next table belongs to a different domain\n");
				goto out_invalid_arg;
			}
			if (action->meter.next_ft->level <=
			    matcher->tbl->level) {
				dr_dbg(dmn, "Next table level should he higher than source table\n");
				goto out_invalid_arg;
			}
			attr.final_icm_addr = rx_rule ?
				action->meter.rx_icm_addr :
				action->meter.tx_icm_addr;
			break;
		case DR_ACTION_TYP_SAMPLER:
			if (action->sampler.dmn != dmn) {
				dr_dbg(dmn, "Sampler belongs to a different domain\n");
				goto out_invalid_arg;
			}
			if (action->sampler.sampler_default->next_ft->level <=
			    matcher->tbl->level) {
				dr_dbg(dmn, "Sampler next table level should he higher than source table\n");
				goto out_invalid_arg;
			}

			if (rx_rule) {
				attr.final_icm_addr = action->sampler.sampler_default->rx_icm_addr;
			} else {
				attr.final_icm_addr = (action->sampler.sampler_restore) ?
						      action->sampler.sampler_restore->tx_icm_addr :
						      action->sampler.sampler_default->tx_icm_addr;
			}
			break;
		case DR_ACTION_TYP_VPORT:
			if (action->vport.dmn != dmn) {
				dr_dbg(dmn, "Destination vport belongs to a different domain\n");
				goto out_invalid_arg;
			}
			attr.hit_gvmi = action->vport.caps->vhca_gvmi;
			if (rx_rule) {
				/* Loopback on WIRE vport is not supported */
				if (action->vport.caps->num == WIRE_PORT)
					goto out_invalid_arg;

				attr.final_icm_addr = action->vport.caps->icm_address_rx;
			} else {
				attr.final_icm_addr = action->vport.caps->icm_address_tx;
			}
			break;
		case DR_ACTION_TYP_DEST_ARRAY:
			if (action->dest_array.dmn != dmn) {
				dr_dbg(dmn, "Destination array belongs to a different domain\n");
				goto out_invalid_arg;
			}

			attr.final_icm_addr = rx_rule ?
				action->dest_array.rx_icm_addr :
				action->dest_array.tx_icm_addr;
			break;
		case DR_ACTION_TYP_POP_VLAN:
			if (!rx_rule && !(dmn->ste_ctx->actions_caps &
					  DR_STE_CTX_ACTION_CAP_TX_POP)) {
				dr_dbg(dmn, "Device doesn't support POP VLAN action on TX\n");
				goto out_invalid_arg;
			}

			max_actions_type = MAX_VLANS;
			attr.vlans.count++;
			break;
		case DR_ACTION_TYP_PUSH_VLAN:
			if (rx_rule && !(dmn->ste_ctx->actions_caps &
					 DR_STE_CTX_ACTION_CAP_RX_PUSH)) {
				dr_dbg(dmn, "Device doesn't support PUSH VLAN action on RX\n");
				goto out_invalid_arg;
			}

			max_actions_type = MAX_VLANS;
			if (attr.vlans.count == MAX_VLANS) {
				errno = ENOTSUP;
				return ENOTSUP;
			}

			attr.vlans.headers[attr.vlans.count++] = action->push_vlan.vlan_hdr;
			break;
		default:
			goto out_invalid_arg;
		}

		/* Check action duplication */
		if (++action_type_set[action_type] > max_actions_type) {
			dr_dbg(dmn, "Action type %d supports only max %d time(s)\n",
			       action_type, max_actions_type);
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

	dr_actions_apply(dmn,
			 nic_dmn->type,
			 action_type_set,
			 last_ste,
			 &attr,
			 new_hw_ste_arr_sz);

	if (attr.aso_ste_loc != -1)
		cross_dmn_p->cross_dmn_loc = attr.aso_ste_loc;

	return 0;

out_invalid_arg:
	errno = EINVAL;
out_errno:
	if (cross_dmn_action) {
		struct dr_aso_cross_dmn_arrays *cross_dmn_arrays = (struct dr_aso_cross_dmn_arrays *) cross_dmn_action->aso.devx_obj->priv;

		atomic_fetch_sub(&cross_dmn_arrays->rule_htbl[cross_dmn_action->aso.offset]->ste_arr->refcount, 1);
		atomic_fetch_sub(&cross_dmn_arrays->action_htbl[cross_dmn_action->aso.offset]->ste_arr->refcount, 1);
	}
	return errno;
}

int dr_actions_build_attr(struct mlx5dv_dr_matcher *matcher,
			  struct mlx5dv_dr_action *actions[],
			  size_t num_actions,
			  struct mlx5dv_flow_action_attr *attr,
			  struct mlx5_flow_action_attr_aux *attr_aux)
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
		case DR_ACTION_TYP_DEST_ARRAY:
			if (actions[i]->dest_array.dmn != dmn) {
				dr_dbg(dmn, "Destination array belongs to a different domain\n");
				errno = EINVAL;
				return errno;
			}
			attr[i].type = MLX5DV_FLOW_ACTION_DEST_DEVX;
			attr[i].obj = actions[i]->dest_array.devx_tbl->ft_dvo;
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
			if (actions[i]->dest_qp.is_qp) {
				attr[i].type = MLX5DV_FLOW_ACTION_DEST_IBV_QP;
				attr[i].qp = actions[i]->dest_qp.qp;
			} else {
				attr[i].type = MLX5DV_FLOW_ACTION_DEST_DEVX;
				attr[i].obj = actions[i]->dest_qp.devx_tir;
			}
			break;
		case DR_ACTION_TYP_CTR:
			attr[i].type = MLX5DV_FLOW_ACTION_COUNTERS_DEVX;
			attr[i].obj = actions[i]->ctr.devx_obj;

			if (actions[i]->ctr.offset) {
				attr_aux[i].type = MLX5_FLOW_ACTION_COUNTER_OFFSET;
				attr_aux[i].offset = actions[i]->ctr.offset;
			}
			break;
		case DR_ACTION_TYP_TAG:
			attr[i].type = MLX5DV_FLOW_ACTION_TAG;
			attr[i].tag_value = actions[i]->flow_tag;
			break;
		case DR_ACTION_TYP_MISS:
			attr[i].type = MLX5DV_FLOW_ACTION_DEFAULT_MISS;
			break;
		case DR_ACTION_TYP_DROP:
			attr[i].type = MLX5DV_FLOW_ACTION_DROP;
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

struct mlx5dv_dr_action *mlx5dv_dr_action_create_default_miss(void)
{
	return dr_action_create_generic(DR_ACTION_TYP_MISS);
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

	action->dest_qp.is_qp = true;
	action->dest_qp.qp = ibqp;

	return action;
}

struct mlx5dv_dr_action *
mlx5dv_dr_action_create_dest_devx_tir(struct mlx5dv_devx_obj *devx_obj)
{
	struct mlx5dv_dr_action *action;

	if (devx_obj->type != MLX5_DEVX_TIR) {
		errno = EINVAL;
		return NULL;
	}

	action = dr_action_create_generic(DR_ACTION_TYP_QP);
	if (!action)
		return NULL;

	action->dest_qp.devx_tir = devx_obj;
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
				     uint32_t offset)
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
	action->ctr.offset = offset;

	return action;
}

static int
dr_action_aso_first_hit_init(struct mlx5dv_dr_action *action,
			     uint32_t offset,
			     uint32_t flags,
			     uint8_t return_reg_c)
{
	if (!check_comp_mask(flags, MLX5DV_DR_ACTION_FLAGS_ASO_FIRST_HIT_SET)) {
		errno = EINVAL;
		return errno;
	}

	if ((offset / MLX5_ASO_FIRST_HIT_NUM_PER_OBJ) >=
				(1 << action->aso.devx_obj->log_obj_range)) {
		errno = EINVAL;
		return errno;
	}

	if ((return_reg_c > 5) || (return_reg_c % 2 == 0)) {
		errno = EINVAL;
		return errno;
	}

	action->aso.offset = offset;
	action->aso.first_hit.set = flags & MLX5DV_DR_ACTION_FLAGS_ASO_FIRST_HIT_SET;
	action->aso.dest_reg_id = return_reg_c;

	return 0;
}

static int
dr_action_aso_flow_meter_init(struct mlx5dv_dr_action *action,
			      uint32_t offset,
			      uint32_t flags,
			      uint8_t return_reg_c)
{
	if (!flags ||
	    (flags > MLX5DV_DR_ACTION_FLAGS_ASO_FLOW_METER_UNDEFINED)) {
		errno = EINVAL;
		return errno;
	}

	if ((offset / MLX5_ASO_FLOW_METER_NUM_PER_OBJ) >=
				(1 << action->aso.devx_obj->log_obj_range)) {
		errno = EINVAL;
		return errno;
	}

	if ((return_reg_c > 5) || (return_reg_c % 2 == 0)) {
		errno = EINVAL;
		return errno;
	}

	switch (flags) {
	case MLX5DV_DR_ACTION_FLAGS_ASO_FLOW_METER_RED:
		action->aso.flow_meter.initial_color =
			MLX5_IFC_ASO_FLOW_METER_INITIAL_COLOR_RED;
		break;
	case MLX5DV_DR_ACTION_FLAGS_ASO_FLOW_METER_YELLOW:
		action->aso.flow_meter.initial_color =
			MLX5_IFC_ASO_FLOW_METER_INITIAL_COLOR_YELLOW;
		break;
	case MLX5DV_DR_ACTION_FLAGS_ASO_FLOW_METER_GREEN:
		action->aso.flow_meter.initial_color =
			MLX5_IFC_ASO_FLOW_METER_INITIAL_COLOR_GREEN;
		break;
	case MLX5DV_DR_ACTION_FLAGS_ASO_FLOW_METER_UNDEFINED:
		action->aso.flow_meter.initial_color =
			MLX5_IFC_ASO_FLOW_METER_INITIAL_COLOR_UNDEFINED;
		break;
	default:
		errno = EINVAL;
		return errno;
	}

	action->aso.offset = offset;
	action->aso.dest_reg_id = return_reg_c;

	return 0;
}

static int
dr_action_aso_ct_init(struct mlx5dv_dr_action *action,
		      uint32_t offset,
		      uint32_t flags,
		      uint8_t return_reg_c)
{
	if (!flags ||
	    (flags > MLX5DV_DR_ACTION_FLAGS_ASO_CT_DIRECTION_RESPONDER))
		goto err_invalid;

	if ((offset / MLX5_ASO_CT_NUM_PER_OBJ) >=
				(1 << action->aso.devx_obj->log_obj_range))
		goto err_invalid;

	if ((return_reg_c > 5) || (return_reg_c % 2 == 0))
		goto err_invalid;

	if (flags == MLX5DV_DR_ACTION_FLAGS_ASO_CT_DIRECTION_INITIATOR)
		action->aso.ct.direction = MLX5_IFC_ASO_CT_DIRECTION_INITIATOR;
	else
		action->aso.ct.direction = MLX5_IFC_ASO_CT_DIRECTION_RESPONDER;

	action->aso.offset = offset;
	action->aso.dest_reg_id = return_reg_c;

	return 0;

err_invalid:
	errno = EINVAL;
	return errno;
}

struct mlx5dv_dr_action *
mlx5dv_dr_action_create_aso(struct mlx5dv_dr_domain *dmn,
			    struct mlx5dv_devx_obj *devx_obj,
			    uint32_t offset,
			    uint32_t flags,
			    uint8_t return_reg_c)
{
	struct mlx5dv_dr_action *action = NULL;

	if (!dmn->info.supp_sw_steering ||
	    dmn->info.caps.sw_format_ver != MLX5_HW_CONNECTX_6DX) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	if (devx_obj->type == MLX5_DEVX_ASO_FIRST_HIT) {
		action = dr_action_create_generic(DR_ACTION_TYP_ASO_FIRST_HIT);
		if (!action)
			return NULL;

		action->aso.devx_obj = devx_obj;

		if (dr_action_aso_first_hit_init(action, offset,
						 flags, return_reg_c))
			goto out_free;
	} else if (devx_obj->type == MLX5_DEVX_ASO_FLOW_METER) {
		action = dr_action_create_generic(DR_ACTION_TYP_ASO_FLOW_METER);
		if (!action)
			return NULL;

		action->aso.devx_obj = devx_obj;

		if (dr_action_aso_flow_meter_init(action, offset,
						  flags, return_reg_c))
			goto out_free;
	} else if (devx_obj->type == MLX5_DEVX_ASO_CT) {
		action = dr_action_create_generic(DR_ACTION_TYP_ASO_CT);
		if (!action)
			return NULL;

		action->aso.devx_obj = devx_obj;

		if (dr_action_aso_ct_init(action, offset, flags, return_reg_c))
			goto out_free;
	} else {
		errno = EOPNOTSUPP;
		return NULL;
	}

	action->aso.dmn = dmn;

	return action;

out_free:
	free(action);
	return NULL;
}

static int
dr_action_aso_ct_modify(struct mlx5dv_dr_action *action,
			uint32_t offset,
			uint32_t flags,
			uint8_t return_reg_c)
{
	if (action->aso.devx_obj->priv == NULL)
		return dr_action_aso_ct_init(action, offset,
					     flags, return_reg_c);

	if (action->aso.dest_reg_id != return_reg_c) {
		dr_dbg(action->aso.dmn, "Invalid parameters for a cross gvmi action\n");
		errno = EOPNOTSUPP;
		return errno;
	}

	if (flags > MLX5DV_DR_ACTION_FLAGS_ASO_CT_DIRECTION_RESPONDER) {
		errno = EOPNOTSUPP;
		return errno;
	}

	if ((flags == MLX5DV_DR_ACTION_FLAGS_ASO_CT_DIRECTION_INITIATOR &&
	    action->aso.ct.direction != MLX5_IFC_ASO_CT_DIRECTION_INITIATOR) ||
	    (flags == MLX5DV_DR_ACTION_FLAGS_ASO_CT_DIRECTION_RESPONDER &&
	    action->aso.ct.direction != MLX5_IFC_ASO_CT_DIRECTION_RESPONDER)) {
		errno = EOPNOTSUPP;
		return errno;
	}

	action->aso.offset = offset;

	return 0;
}

int mlx5dv_dr_action_modify_aso(struct mlx5dv_dr_action *action,
				uint32_t offset,
				uint32_t flags,
				uint8_t return_reg_c)
{
	if (action->action_type == DR_ACTION_TYP_ASO_FIRST_HIT)
		return dr_action_aso_first_hit_init(action, offset,
						    flags, return_reg_c);
	else if (action->action_type == DR_ACTION_TYP_ASO_FLOW_METER)
		return dr_action_aso_flow_meter_init(action, offset,
						     flags, return_reg_c);
	else if (action->action_type == DR_ACTION_TYP_ASO_CT)
		return dr_action_aso_ct_modify(action, offset,
					       flags, return_reg_c);

	errno = EINVAL;
	return errno;
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
		uint8_t hw_actions[ACTION_CACHE_LINE_SIZE] = {};
		int ret;

		ret = dr_ste_set_action_decap_l3_list(dmn->ste_ctx,
						      data, data_sz,
						      hw_actions,
						      ACTION_CACHE_LINE_SIZE,
						      &action->rewrite.num_of_actions);
		if (ret) {
			dr_dbg(dmn, "Failed creating decap l3 action list\n");
			return ret;
		}

		action->rewrite.chunk = dr_icm_alloc_chunk(dmn->action_icm_pool,
							   DR_CHUNK_SIZE_8);
		if (!action->rewrite.chunk) {
			dr_dbg(dmn, "Failed allocating modify header chunk\n");
			return errno;
		}

		action->rewrite.data = (void *)hw_actions;
		action->rewrite.index = (action->rewrite.chunk->icm_addr -
					 dmn->info.caps.hdr_modify_icm_addr) /
					 ACTION_CACHE_LINE_SIZE;

		ret = dr_send_postsend_action(dmn, action);
		if (ret) {
			dr_dbg(dmn, "Writing decap l3 actions to ICM failed\n");
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

struct mlx5dv_dr_action *mlx5dv_dr_action_create_pop_vlan(void)
{
	return dr_action_create_generic(DR_ACTION_TYP_POP_VLAN);
}

struct mlx5dv_dr_action *mlx5dv_dr_action_create_push_vlan(struct mlx5dv_dr_domain *dmn,
							   __be32 vlan_hdr)
{
	uint32_t vlan_hdr_h = be32toh(vlan_hdr);
	uint16_t ethertype = vlan_hdr_h >> 16;
	struct mlx5dv_dr_action *action;

	if (ethertype != SVLAN_ETHERTYPE && ethertype != CVLAN_ETHERTYPE) {
		dr_dbg(dmn, "Invalid vlan ethertype\n");
		errno = EINVAL;
		return NULL;
	}

	action = dr_action_create_generic(DR_ACTION_TYP_PUSH_VLAN);
	if (!action)
		return NULL;

	action->push_vlan.vlan_hdr = vlan_hdr_h;
	return action;
}

static int
dr_action_modify_sw_to_hw_add(struct mlx5dv_dr_domain *dmn,
			      __be64 *sw_action,
			      __be64 *hw_action,
			      const struct dr_ste_action_modify_field **ret_hw_info)
{
	const struct dr_ste_action_modify_field *hw_action_info;
	uint8_t max_length;
	uint16_t sw_field;
	uint32_t data;

	/* Get SW modify action data */
	sw_field = DEVX_GET(set_action_in, sw_action, field);
	data = DEVX_GET(set_action_in, sw_action, data);

	/* Convert SW data to HW modify action format */
	hw_action_info = dr_ste_conv_modify_hdr_sw_field(dmn->ste_ctx,
							 &dmn->info.caps,
							 sw_field);
	if (!hw_action_info) {
		dr_dbg(dmn, "Modify ADD action invalid field given\n");
		errno = EINVAL;
		return errno;
	}

	max_length = hw_action_info->end - hw_action_info->start + 1;

	dr_ste_set_action_add(dmn->ste_ctx,
			      hw_action,
			      hw_action_info->hw_field,
			      hw_action_info->start,
			      max_length, data);

	*ret_hw_info = hw_action_info;

	return 0;
}

static int
dr_action_modify_sw_to_hw_set(struct mlx5dv_dr_domain *dmn,
			      __be64 *sw_action,
			      __be64 *hw_action,
			      const struct dr_ste_action_modify_field **ret_hw_info)
{
	const struct dr_ste_action_modify_field *hw_action_info;
	uint8_t offset, length, max_length;
	uint16_t sw_field;
	uint32_t data;

	/* Get SW modify action data */
	sw_field = DEVX_GET(set_action_in, sw_action, field);
	offset = DEVX_GET(set_action_in, sw_action, offset);
	length = DEVX_GET(set_action_in, sw_action, length);
	data = DEVX_GET(set_action_in, sw_action, data);

	/* Convert SW data to HW modify action format */
	hw_action_info = dr_ste_conv_modify_hdr_sw_field(dmn->ste_ctx,
							 &dmn->info.caps,
							 sw_field);
	if (!hw_action_info) {
		dr_dbg(dmn, "Modify SET action invalid field given\n");
		errno = EINVAL;
		return errno;
	}

	/* Based on device specification value of 0 means 32 */
	length = length ? length : 32;
	max_length = hw_action_info->end - hw_action_info->start + 1;

	if (length + offset > max_length) {
		dr_dbg(dmn, "Modify action length + offset exceeds limit\n");
		errno = EINVAL;
		return errno;
	}

	dr_ste_set_action_set(dmn->ste_ctx,
			      hw_action,
			      hw_action_info->hw_field,
			      hw_action_info->start + offset,
			      length, data);

	*ret_hw_info = hw_action_info;

	return 0;
}

static int
dr_action_modify_sw_to_hw_copy(struct mlx5dv_dr_domain *dmn,
			       __be64 *sw_action,
			       __be64 *hw_action,
			       const struct dr_ste_action_modify_field **ret_dst_hw_info,
			       const struct dr_ste_action_modify_field **ret_src_hw_info)
{
	uint8_t src_offset, dst_offset, src_max_length, dst_max_length, length;
	const struct dr_ste_action_modify_field *src_hw_action_info;
	const struct dr_ste_action_modify_field *dst_hw_action_info;
	uint16_t src_field, dst_field;

	/* Get SW modify action data */
	src_field = DEVX_GET(copy_action_in, sw_action, src_field);
	dst_field = DEVX_GET(copy_action_in, sw_action, dst_field);
	src_offset = DEVX_GET(copy_action_in, sw_action, src_offset);
	dst_offset = DEVX_GET(copy_action_in, sw_action, dst_offset);
	length = DEVX_GET(copy_action_in, sw_action, length);

	/* Convert SW data to HW modify action format */
	src_hw_action_info = dr_ste_conv_modify_hdr_sw_field(dmn->ste_ctx,
							     &dmn->info.caps,
							     src_field);
	dst_hw_action_info = dr_ste_conv_modify_hdr_sw_field(dmn->ste_ctx,
							     &dmn->info.caps,
							     dst_field);
	if (!src_hw_action_info || !dst_hw_action_info) {
		dr_dbg(dmn, "Modify COPY action invalid src/dst field given\n");
		errno = EINVAL;
		return errno;
	}

	/* Based on device specification value of 0 means 32 */
	length = length ? length : 32;

	src_max_length = src_hw_action_info->end - src_hw_action_info->start + 1;
	dst_max_length = dst_hw_action_info->end - dst_hw_action_info->start + 1;
	if (length + src_offset > src_max_length ||
	    length + dst_offset > dst_max_length) {
		dr_dbg(dmn, "Modify action length exceeds limit\n");
		errno = EINVAL;
		return errno;
	}

	dr_ste_set_action_copy(dmn->ste_ctx,
			       hw_action,
			       dst_hw_action_info->hw_field,
			       dst_hw_action_info->start + dst_offset,
			       length,
			       src_hw_action_info->hw_field,
			       src_hw_action_info->start + src_offset);

	*ret_dst_hw_info = dst_hw_action_info;
	*ret_src_hw_info = src_hw_action_info;

	return 0;
}

static int
dr_action_modify_sw_to_hw(struct mlx5dv_dr_domain *dmn,
			  __be64 *sw_action,
			  __be64 *hw_action,
			  const struct dr_ste_action_modify_field **ret_dst_hw_info,
			  const struct dr_ste_action_modify_field **ret_src_hw_info)
{
	uint8_t action = DEVX_GET(set_action_in, sw_action, action_type);
	int ret = 0;

	*hw_action = 0;
	*ret_src_hw_info = NULL;

	switch (action) {
	case MLX5_ACTION_TYPE_SET:
		ret = dr_action_modify_sw_to_hw_set(dmn,
						    sw_action,
						    hw_action,
						    ret_dst_hw_info);
		break;
	case MLX5_ACTION_TYPE_ADD:
		ret = dr_action_modify_sw_to_hw_add(dmn,
						    sw_action,
						    hw_action,
						    ret_dst_hw_info);
		break;
	case MLX5_ACTION_TYPE_COPY:
		ret = dr_action_modify_sw_to_hw_copy(dmn,
						     sw_action,
						     hw_action,
						     ret_dst_hw_info,
						     ret_src_hw_info);
		break;
	default:
		dr_dbg(dmn, "Unsupported action type %d for modify action\n",
		       action);
		errno = EOPNOTSUPP;
		ret = errno;
		break;
	}

	return ret;
}

static int
dr_action_modify_check_field_limitation_set(struct mlx5dv_dr_action *action,
					    const __be64 *sw_action)
{
	uint16_t sw_field = DEVX_GET(set_action_in, sw_action, field);
	struct mlx5dv_dr_domain *dmn = action->rewrite.dmn;

	if (sw_field == MLX5_ACTION_IN_FIELD_OUT_METADATA_REGA) {
		action->rewrite.allow_rx = false;
		if (dmn->type != MLX5DV_DR_DOMAIN_TYPE_NIC_TX) {
			dr_dbg(dmn, "Unsupported field %d for RX/FDB set action\n",
			       sw_field);
			errno = EINVAL;
			return errno;
		}
	} else if (sw_field == MLX5_ACTION_IN_FIELD_OUT_METADATA_REGB) {
		action->rewrite.allow_tx = false;
		if (dmn->type != MLX5DV_DR_DOMAIN_TYPE_NIC_RX) {
			dr_dbg(dmn, "Unsupported field %d for TX/FDB set action\n",
			       sw_field);
			errno = EINVAL;
			return errno;
		}
	}

	if (!action->rewrite.allow_rx && !action->rewrite.allow_tx) {
		dr_dbg(dmn, "Modify SET actions not supported on both RX and TX\n");
		errno = EINVAL;
		return errno;
	}

	return 0;
}

static int
dr_action_modify_check_field_limitation_add(struct mlx5dv_dr_action *action,
					    const __be64 *sw_action)
{
	uint16_t sw_field = DEVX_GET(add_action_in, sw_action, field);

	if (sw_field != MLX5_ACTION_IN_FIELD_OUT_IP_TTL &&
	    sw_field != MLX5_ACTION_IN_FIELD_OUT_IPV6_HOPLIMIT &&
	    sw_field != MLX5_ACTION_IN_FIELD_OUT_TCP_SEQ_NUM &&
	    sw_field != MLX5_ACTION_IN_FIELD_OUT_TCP_ACK_NUM) {
		dr_dbg(action->rewrite.dmn,
		       "Unsupported field %d for ADD action\n", sw_field);
		errno = EINVAL;
		return errno;
	}

	return 0;
}

static int
dr_action_modify_check_field_limitation_copy(struct mlx5dv_dr_action *action,
					     const __be64 *sw_action)
{
	struct mlx5dv_dr_domain *dmn = action->rewrite.dmn;
	uint16_t sw_fields[2];
	int i;

	sw_fields[0] = DEVX_GET(copy_action_in, sw_action, src_field);
	sw_fields[1] = DEVX_GET(copy_action_in, sw_action, dst_field);

	for (i = 0; i < 2; i++) {
		if (sw_fields[i] == MLX5_ACTION_IN_FIELD_OUT_METADATA_REGA) {
			action->rewrite.allow_rx = false;
			if (dmn->type != MLX5DV_DR_DOMAIN_TYPE_NIC_TX) {
				dr_dbg(dmn, "Unsupported field %d for RX/FDB COPY action\n",
				       sw_fields[i]);
				errno = EINVAL;
				return errno;
			}
		} else if (sw_fields[i] == MLX5_ACTION_IN_FIELD_OUT_METADATA_REGB) {
			action->rewrite.allow_tx = false;
			if (dmn->type != MLX5DV_DR_DOMAIN_TYPE_NIC_RX) {
				dr_dbg(dmn, "Unsupported field %d for TX/FDB COPY action\n",
				       sw_fields[i]);
				errno = EINVAL;
				return errno;
			}
		}
	}

	if (!action->rewrite.allow_rx && !action->rewrite.allow_tx) {
		dr_dbg(dmn, "Modify actions combination is not supported on both RX and TX\n");
		errno = EINVAL;
		return errno;
	}

	return 0;
}

static int
dr_action_modify_check_field_limitation(struct mlx5dv_dr_action *action,
					const __be64 *sw_action)
{
	uint8_t action_type = DEVX_GET(set_action_in, sw_action, action_type);
	struct mlx5dv_dr_domain *dmn = action->rewrite.dmn;
	int ret;

	switch (action_type) {
	case MLX5_ACTION_TYPE_SET:
		ret = dr_action_modify_check_field_limitation_set(action,
								  sw_action);
		break;
	case MLX5_ACTION_TYPE_ADD:
		ret = dr_action_modify_check_field_limitation_add(action,
								  sw_action);
		break;
	case MLX5_ACTION_TYPE_COPY:
		ret = dr_action_modify_check_field_limitation_copy(action,
								   sw_action);
		break;
	default:
		dr_dbg(dmn, "Unsupported modify action %d\n",
			action_type);
		errno = EOPNOTSUPP;
		ret = errno;
		break;
	}

	return ret;
}

static int dr_actions_convert_modify_header(struct mlx5dv_dr_action *action,
					    uint32_t max_hw_actions,
					    uint32_t num_sw_actions,
					    __be64 sw_actions[],
					    __be64 hw_actions[],
					    uint32_t *num_hw_actions)
{
	const struct dr_ste_action_modify_field *hw_dst_action_info;
	const struct dr_ste_action_modify_field *hw_src_action_info;
	struct mlx5dv_dr_domain *dmn = action->rewrite.dmn;
	int ret, i, hw_idx = 0;
	uint16_t hw_field = 0;
	uint32_t l3_type = 0;
	uint32_t l4_type = 0;
	__be64 *sw_action;
	__be64 hw_action;

	action->rewrite.allow_rx = true;
	action->rewrite.allow_tx = true;

	for (i = 0; i < num_sw_actions; i++) {
		sw_action = &sw_actions[i];

		ret = dr_action_modify_check_field_limitation(action,
							      sw_action);
		if (ret)
			return ret;

		/* Convert SW action to HW action */
		ret = dr_action_modify_sw_to_hw(dmn,
						sw_action,
						&hw_action,
						&hw_dst_action_info,
						&hw_src_action_info);
		if (ret)
			return ret;

		/* Due to a HW limitation we cannot modify 2 different L3 types */
		if (l3_type && hw_dst_action_info->l3_type &&
		    (hw_dst_action_info->l3_type != l3_type)) {
			dr_dbg(dmn, "Action list can't support two different L3 types\n");
			errno = ENOTSUP;
			return errno;
		}
		if (hw_dst_action_info->l3_type)
			l3_type = hw_dst_action_info->l3_type;

		/* Due to a HW limitation we cannot modify two different L4 types */
		if (l4_type && hw_dst_action_info->l4_type &&
		    (hw_dst_action_info->l4_type != l4_type)) {
			dr_dbg(dmn, "Action list can't support two different L4 types\n");
			errno = EINVAL;
			return errno;
		}
		if (hw_dst_action_info->l4_type)
			l4_type = hw_dst_action_info->l4_type;

		/* HW reads and executes two actions at once this means we
		 * need to create a gap if two actions access the same field
		 */
		if ((hw_idx % 2) && (hw_field == hw_dst_action_info->hw_field ||
				     (hw_src_action_info &&
				      hw_field == hw_src_action_info->hw_field))) {
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
		hw_field = hw_dst_action_info->hw_field;

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
	uint32_t dynamic_chunck_size;
	struct dr_icm_chunk *chunk;
	uint32_t num_hw_actions;
	uint32_t num_sw_actions;
	__be64 *hw_actions;
	int ret;

	num_sw_actions = actions_sz / DR_MODIFY_ACTION_SIZE;
	if (num_sw_actions == 0) {
		dr_dbg(dmn, "Invalid number of actions %u\n", num_sw_actions);
		errno = EINVAL;
		return errno;
	}

	hw_actions = calloc(1, 2 * num_sw_actions  * DR_MODIFY_ACTION_SIZE);
	if (!hw_actions) {
		errno = ENOMEM;
		return errno;
	}

	ret = dr_actions_convert_modify_header(action,
					       2 * num_sw_actions,
					       num_sw_actions,
					       actions,
					       hw_actions,
					       &num_hw_actions);
	if (ret)
		goto free_hw_actions;

	dynamic_chunck_size = ilog32(num_hw_actions - 1);

	/* HW modify action index granularity is at least 64B */
	dynamic_chunck_size = max_t(uint32_t, dynamic_chunck_size,
				    DR_CHUNK_SIZE_8);

	chunk = dr_icm_alloc_chunk(dmn->action_icm_pool, dynamic_chunck_size);
	if (!chunk)
		goto free_hw_actions;

	action->rewrite.chunk = chunk;
	action->rewrite.data = (uint8_t *)hw_actions;
	action->rewrite.num_of_actions = num_hw_actions;
	action->rewrite.index = (chunk->icm_addr -
				 dmn->info.caps.hdr_modify_icm_addr) /
				 ACTION_CACHE_LINE_SIZE;

	ret = dr_send_postsend_action(dmn, action);
	if (ret)
		goto free_chunk;

	return 0;

free_chunk:
	dr_icm_free_chunk(chunk);
free_hw_actions:
	free(hw_actions);
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

int mlx5dv_dr_action_modify_flow_meter(struct mlx5dv_dr_action *action,
				       struct mlx5dv_dr_flow_meter_attr *attr,
				       __be64 modify_field_select)
{
	int ret;

	if (action->action_type != DR_ACTION_TYP_METER) {
		errno = EINVAL;
		return errno;
	}

	ret = dr_devx_modify_meter(action->meter.devx_obj, attr,
				   modify_field_select);
	return ret;
}

struct mlx5dv_dr_action *
mlx5dv_dr_action_create_flow_meter(struct mlx5dv_dr_flow_meter_attr *attr)
{
	struct mlx5dv_dr_domain *dmn = attr->next_table->dmn;
	uint64_t rx_icm_addr, tx_icm_addr;
	struct mlx5dv_devx_obj *devx_obj;
	struct mlx5dv_dr_action *action;
	int ret;

	if (!dmn->info.supp_sw_steering) {
		dr_dbg(dmn, "Meter action is not supported on current domain\n");
		errno = EOPNOTSUPP;
		return NULL;
	}

	if (dr_is_root_table(attr->next_table)) {
		dr_dbg(dmn, "Next table cannot be root\n");
		errno = EOPNOTSUPP;
		return NULL;
	}

	devx_obj = dr_devx_create_meter(dmn->ctx, attr);
	if (!devx_obj)
		return NULL;

	ret = dr_devx_query_meter(devx_obj, &rx_icm_addr, &tx_icm_addr);
	if (ret)
		goto destroy_obj;

	action = dr_action_create_generic(DR_ACTION_TYP_METER);
	if (!action)
		goto destroy_obj;

	action->meter.devx_obj = devx_obj;
	action->meter.next_ft = attr->next_table;
	action->meter.rx_icm_addr = rx_icm_addr;
	action->meter.tx_icm_addr = tx_icm_addr;

	atomic_fetch_add(&attr->next_table->refcount, 1);

	return action;

destroy_obj:
	mlx5dv_devx_obj_destroy(devx_obj);
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

	/* vport number is limited to 16 bit */
	if (vport > WIRE_PORT) {
		dr_dbg(dmn, "The vport number is out of range\n");
		errno = EINVAL;
		return NULL;
	}

	vport_cap = dr_vports_table_get_vport_cap(&dmn->info.caps, vport);
	if (!vport_cap) {
		dr_dbg(dmn, "Failed to get vport %d caps\n", vport);
		return NULL;
	}

	action = dr_action_create_generic(DR_ACTION_TYP_VPORT);
	if (!action)
		return NULL;

	action->vport.dmn = dmn;
	action->vport.caps = vport_cap;

	return action;
}

struct mlx5dv_dr_action *
mlx5dv_dr_action_create_dest_ib_port(struct mlx5dv_dr_domain *dmn,
				     uint32_t ib_port)
{
	struct dr_devx_vport_cap *vport_cap;
	struct mlx5dv_dr_action *action;

	if (!dmn->info.supp_sw_steering ||
	    dmn->type != MLX5DV_DR_DOMAIN_TYPE_FDB) {
		dr_dbg(dmn, "Domain doesn't support ib_port actions\n");
		errno = EOPNOTSUPP;
		return NULL;
	}

	vport_cap = dr_vports_table_get_ib_port_cap(&dmn->info.caps, ib_port);
	if (!vport_cap) {
		dr_dbg(dmn, "Failed to get ib_port %d caps\n", ib_port);
		errno = EINVAL;
		return NULL;
	}

	action = dr_action_create_generic(DR_ACTION_TYP_VPORT);
	if (!action)
		return NULL;

	action->vport.dmn = dmn;
	action->vport.caps = vport_cap;

	return action;
}

static int
dr_action_convert_to_fte_dest(struct mlx5dv_dr_domain *dmn,
			      struct mlx5dv_dr_action *dest,
			      struct mlx5dv_dr_action *dest_reformat,
			      struct dr_devx_flow_fte_attr *fte_attr)
{
	struct dr_devx_flow_dest_info *dest_info =
		&fte_attr->dest_arr[fte_attr->dest_size];

	switch (dest->action_type) {
	case DR_ACTION_TYP_MISS:
		if (dmn->type != MLX5DV_DR_DOMAIN_TYPE_FDB)
			goto err_exit;

		fte_attr->action |= MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
		dest_info->type = MLX5_FLOW_DEST_TYPE_VPORT;
		break;
	case DR_ACTION_TYP_VPORT:
		if (dmn->type != MLX5DV_DR_DOMAIN_TYPE_FDB)
			goto err_exit;

		fte_attr->action |= MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
		dest_info->type = MLX5_FLOW_DEST_TYPE_VPORT;
		dest_info->vport_num = dest->vport.caps->num;
		break;
	case DR_ACTION_TYP_QP:
		fte_attr->action |= MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
		dest_info->type = MLX5_FLOW_DEST_TYPE_TIR;

		if (dest->dest_qp.is_qp)
			dest_info->tir_num = to_mqp(dest->dest_qp.qp)->tirn;
		else
			dest_info->tir_num = dest->dest_qp.devx_tir->object_id;

		break;
	case DR_ACTION_TYP_CTR:
		fte_attr->action |= MLX5_FLOW_CONTEXT_ACTION_COUNT;
		dest_info->type = MLX5_FLOW_DEST_TYPE_COUNTER;
		dest_info->counter_id =
			dest->ctr.devx_obj->object_id + dest->ctr.offset;
		break;
	case DR_ACTION_TYP_FT:
		fte_attr->action |= MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
		dest_info->type = MLX5_FLOW_DEST_TYPE_FT;
		dest_info->ft_id = dest->dest_tbl->devx_obj->object_id;
		break;
	default:
		goto err_exit;
	}

	if (dest_reformat) {
		switch (dest_reformat->action_type) {
		case DR_ACTION_TYP_L2_TO_TNL_L2:
		case DR_ACTION_TYP_L2_TO_TNL_L3:
			if (dest_reformat->reformat.is_root_level)
				goto err_exit;

			fte_attr->extended_dest = true;
			dest_info->has_reformat = true;
			dest_info->reformat_id = dest_reformat->reformat.dvo->object_id;
			break;
		default:
			goto err_exit;
		}
	}

	fte_attr->dest_size++;
	return 0;

err_exit:
	errno = EOPNOTSUPP;
	return errno;
}

static struct dr_devx_tbl_with_refs *
dr_action_create_sampler_term_tbl(struct mlx5dv_dr_domain *dmn,
				  struct mlx5dv_dr_flow_sampler_attr *attr)
{
	struct dr_devx_flow_table_attr ft_attr = {};
	struct dr_devx_flow_group_attr fg_attr = {};
	struct dr_devx_flow_fte_attr fte_attr = {};
	struct dr_devx_flow_dest_info *dest_info;
	struct dr_devx_tbl_with_refs *term_tbl;
	struct mlx5dv_dr_action **ref_actions;
	uint32_t ref_index = 0;
	uint32_t tbl_type;
	uint32_t i;

	tbl_type = attr->default_next_table->table_type;

	dest_info = calloc(attr->num_sample_actions,
			   sizeof(struct dr_devx_flow_dest_info));
	if (!dest_info) {
		errno = ENOMEM;
		return NULL;
	}

	term_tbl = calloc(1, sizeof(struct dr_devx_tbl_with_refs));
	if (!term_tbl) {
		errno = ENOMEM;
		goto free_dest_info;
	}

	ref_actions = calloc(attr->num_sample_actions,
			     sizeof(struct mlx5dv_dr_action *));
	if (!ref_actions) {
		errno = ENOMEM;
		goto free_term_tbl;
	}

	ft_attr.type = tbl_type;
	ft_attr.level = dmn->info.caps.max_ft_level - 1;
	ft_attr.term_tbl = true;
	fte_attr.dest_arr = dest_info;

	for (i = 0; i < attr->num_sample_actions; i++) {
		enum dr_action_type action_type =
			attr->sample_actions[i]->action_type;

		atomic_fetch_add(&attr->sample_actions[i]->refcount, 1);
		ref_actions[ref_index++] = attr->sample_actions[i];

		switch (action_type) {
		case DR_ACTION_TYP_MISS:
		case DR_ACTION_TYP_VPORT:
			if (dr_action_convert_to_fte_dest(dmn, attr->sample_actions[i],
							  NULL, &fte_attr))
				goto free_ref_actions;

			break;
		case DR_ACTION_TYP_QP:
		case DR_ACTION_TYP_CTR:
			if (tbl_type != FS_FT_NIC_RX) {
				errno = EOPNOTSUPP;
				goto free_ref_actions;
			}

			if (dr_action_convert_to_fte_dest(dmn, attr->sample_actions[i],
							  NULL, &fte_attr))
				goto free_ref_actions;

			break;
		case DR_ACTION_TYP_TAG:
			if (tbl_type != FS_FT_NIC_RX) {
				errno = EOPNOTSUPP;
				goto free_ref_actions;
			}

			fte_attr.flow_tag = attr->sample_actions[i]->flow_tag;
			break;
		default:
			errno = EOPNOTSUPP;
			goto free_ref_actions;
		}
	}

	term_tbl->devx_tbl = dr_devx_create_always_hit_ft(dmn->ctx, &ft_attr,
							  &fg_attr, &fte_attr);
	if (!term_tbl->devx_tbl)
		goto free_ref_actions;

	term_tbl->ref_actions = ref_actions;
	term_tbl->ref_actions_num = attr->num_sample_actions;

	free(dest_info);
	return term_tbl;

free_ref_actions:
	for (i = 0; i < ref_index; i++)
		atomic_fetch_sub(&ref_actions[i]->refcount, 1);
	free(ref_actions);
free_term_tbl:
	free(term_tbl);
free_dest_info:
	free(dest_info);

	return NULL;
}

static void
dr_action_destroy_sampler_term_tbl(struct dr_devx_tbl_with_refs *term_tbl)
{
	uint32_t i;

	dr_devx_destroy_always_hit_ft(term_tbl->devx_tbl);

	for (i = 0; i < term_tbl->ref_actions_num; i++)
		atomic_fetch_sub(&term_tbl->ref_actions[i]->refcount, 1);
	free(term_tbl->ref_actions);
	free(term_tbl);
}

static struct dr_flow_sampler *
dr_action_create_sampler(struct mlx5dv_dr_domain *dmn,
			 struct mlx5dv_dr_flow_sampler_attr *attr,
			 struct dr_devx_tbl_with_refs *term_tbl,
			 struct dr_flow_sampler_restore_tbl *restore)
{
	struct dr_devx_flow_sampler_attr sampler_attr = {};
	struct dr_flow_sampler *sampler;
	uint64_t icm_rx, icm_tx;
	int ret;

	sampler = calloc(1, sizeof(struct dr_flow_sampler));
	if (!sampler) {
		errno = ENOMEM;
		return NULL;
	}

	sampler->next_ft = restore ? restore->tbl : attr->default_next_table;
	atomic_fetch_add(&sampler->next_ft->refcount, 1);

	/* Sampler HW level equals to term_tbl HW level, need to set ignore level */
	sampler_attr.ignore_flow_level = true;
	sampler_attr.sample_ratio = attr->sample_ratio;
	sampler_attr.table_type = term_tbl->devx_tbl->type;
	sampler_attr.level = term_tbl->devx_tbl->level;
	sampler_attr.sample_table_id = term_tbl->devx_tbl->ft_dvo->object_id;
	sampler_attr.default_next_table_id = sampler->next_ft->devx_obj->object_id;

	sampler->devx_obj = dr_devx_create_flow_sampler(dmn->ctx, &sampler_attr);
	if (!sampler->devx_obj)
		goto dec_next_ft_ref;

	ret = dr_devx_query_flow_sampler(sampler->devx_obj, &icm_rx, &icm_tx);
	if (ret)
		goto destroy_sampler_dvo;

	sampler->rx_icm_addr = icm_rx;
	sampler->tx_icm_addr = icm_tx;

	return sampler;

destroy_sampler_dvo:
	mlx5dv_devx_obj_destroy(sampler->devx_obj);
dec_next_ft_ref:
	atomic_fetch_sub(&sampler->next_ft->refcount, 1);

	free(sampler);

	return NULL;
}

static void dr_action_destroy_sampler(struct dr_flow_sampler *sampler)
{
	mlx5dv_devx_obj_destroy(sampler->devx_obj);
	atomic_fetch_sub(&sampler->next_ft->refcount, 1);
	free(sampler);
}

static struct dr_flow_sampler_restore_tbl *
dr_action_create_sampler_restore_tbl(struct mlx5dv_dr_domain *dmn,
				     struct mlx5dv_dr_flow_sampler_attr *attr)
{
	struct mlx5dv_flow_match_parameters *mask;
	struct dr_flow_sampler_restore_tbl *restore;
	uint32_t action_field;
	uint32_t action_type;
	uint32_t mask_size;

	action_type = DEVX_GET(set_action_in, &(attr->action), action_type);
	action_field = DEVX_GET(set_action_in, &(attr->action), field);

	/* Currently only support restore of setting Reg_C0 */
	if (action_type != MLX5_ACTION_TYPE_SET ||
	    action_field != MLX5_ACTION_IN_FIELD_OUT_METADATA_REGC_0) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	mask_size = sizeof(struct mlx5dv_flow_match_parameters) +
		    sizeof(struct dr_match_param);
	mask = calloc(1, mask_size);
	if (!mask) {
		errno = ENOMEM;
		return NULL;
	}
	mask->match_sz = sizeof(struct dr_match_param);

	restore = calloc(1, sizeof(struct dr_flow_sampler_restore_tbl));
	if (!restore) {
		errno = ENOMEM;
		goto free_mask;
	}

	restore->tbl = mlx5dv_dr_table_create(dmn, attr->default_next_table->level - 1);
	if (!restore->tbl)
		goto free_restore;

	restore->matcher = mlx5dv_dr_matcher_create(restore->tbl, 0, 0, mask);
	if (!restore->matcher)
		goto destroy_restore_tbl;

	restore->num_of_actions = 2;
	restore->actions = calloc(restore->num_of_actions,
				  sizeof(struct mlx5dv_dr_action *));
	if (!restore->actions) {
		errno = ENOMEM;
		goto destroy_restore_matcher;
	}

	restore->actions[0] =
		mlx5dv_dr_action_create_modify_header(dmn, 0,
						      DR_MODIFY_ACTION_SIZE,
						      &(attr->action));
	if (!restore->actions[0])
		goto free_action_list;

	restore->actions[1] =
		mlx5dv_dr_action_create_dest_table(attr->default_next_table);
	if (!restore->actions[1])
		goto destroy_modify_hdr_action;

	restore->rule = mlx5dv_dr_rule_create(restore->matcher, mask,
					      restore->num_of_actions,
					      restore->actions);
	if (!restore->rule)
		goto destroy_dest_action;

	free(mask);
	return restore;

destroy_dest_action:
	mlx5dv_dr_action_destroy(restore->actions[1]);
destroy_modify_hdr_action:
	mlx5dv_dr_action_destroy(restore->actions[0]);
free_action_list:
	free(restore->actions);
destroy_restore_matcher:
	mlx5dv_dr_matcher_destroy(restore->matcher);
destroy_restore_tbl:
	mlx5dv_dr_table_destroy(restore->tbl);
free_restore:
	free(restore);
free_mask:
	free(mask);

	return NULL;
}

static void dr_action_destroy_sampler_restore_tbl(struct dr_flow_sampler_restore_tbl *restore)
{
	uint32_t i;

	mlx5dv_dr_rule_destroy(restore->rule);
	for (i = 0; i < restore->num_of_actions; i++)
		mlx5dv_dr_action_destroy(restore->actions[i]);
	free(restore->actions);

	mlx5dv_dr_matcher_destroy(restore->matcher);
	mlx5dv_dr_table_destroy(restore->tbl);
	free(restore);
}

struct mlx5dv_dr_action *
mlx5dv_dr_action_create_flow_sampler(struct mlx5dv_dr_flow_sampler_attr *attr)
{
	struct mlx5dv_dr_action *action;
	struct mlx5dv_dr_domain *dmn;
	bool restore = false;

	dmn = attr->default_next_table->dmn;
	if (!dmn ||
	    !attr->default_next_table || attr->sample_ratio == 0 ||
	    !attr->sample_actions || attr->num_sample_actions == 0) {
		errno = EINVAL;
		return NULL;
	}

	if (dmn->type != MLX5DV_DR_DOMAIN_TYPE_NIC_RX &&
	    dmn->type != MLX5DV_DR_DOMAIN_TYPE_FDB) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	if (dmn->type == MLX5DV_DR_DOMAIN_TYPE_FDB &&
	    dmn->info.caps.sw_format_ver == MLX5_HW_CONNECTX_5)
		restore = true;

	atomic_fetch_add(&dmn->refcount, 1);

	action = dr_action_create_generic(DR_ACTION_TYP_SAMPLER);
	if (!action)
		goto dec_ref;

	action->sampler.dmn = dmn;

	action->sampler.term_tbl = dr_action_create_sampler_term_tbl(dmn, attr);
	if (!action->sampler.term_tbl)
		goto free_action;

	action->sampler.sampler_default = dr_action_create_sampler(dmn, attr,
								   action->sampler.term_tbl,
								   NULL);
	if (!action->sampler.sampler_default)
		goto destroy_term_tbl;

	if (restore) {
		struct dr_flow_sampler *sampler_restore;

		action->sampler.restore_tbl = dr_action_create_sampler_restore_tbl(dmn, attr);
		if (!action->sampler.restore_tbl)
			goto destroy_sampler_default;

		sampler_restore = dr_action_create_sampler(dmn, attr,
							   action->sampler.term_tbl,
							   action->sampler.restore_tbl);
		if (!sampler_restore)
			goto destroy_restore;

		action->sampler.sampler_restore = sampler_restore;
	}

	return action;

destroy_restore:
	if (action->sampler.restore_tbl)
		dr_action_destroy_sampler_restore_tbl(action->sampler.restore_tbl);
destroy_sampler_default:
	dr_action_destroy_sampler(action->sampler.sampler_default);
destroy_term_tbl:
	dr_action_destroy_sampler_term_tbl(action->sampler.term_tbl);
free_action:
	free(action);
dec_ref:
	atomic_fetch_sub(&dmn->refcount, 1);

	return NULL;
}

static int dr_action_add_action_member(struct list_head *ref_list,
				       struct mlx5dv_dr_action *action)
{
	struct dr_rule_action_member *action_mem;

	action_mem = calloc(1, sizeof(*action_mem));
	if (!action_mem) {
		errno = ENOMEM;
		return errno;
	}

	action_mem->action = action;
	list_node_init(&action_mem->list);
	list_add_tail(ref_list, &action_mem->list);
	atomic_fetch_add(&action_mem->action->refcount, 1);

	return 0;
}

static void dr_action_remove_action_members(struct list_head *ref_list)
{
	struct dr_rule_action_member *action_mem;
	struct dr_rule_action_member *tmp;

	list_for_each_safe(ref_list, action_mem, tmp, list) {
		list_del(&action_mem->list);
		atomic_fetch_sub(&action_mem->action->refcount, 1);
		free(action_mem);
	}
}

static int
dr_action_create_dest_array_tbl(struct mlx5dv_dr_action *action,
				size_t num_dest,
				struct mlx5dv_dr_action_dest_attr *dests[])
{
	struct mlx5dv_dr_domain *dmn = action->dest_array.dmn;
	struct dr_devx_flow_table_attr ft_attr = {};
	struct dr_devx_flow_group_attr fg_attr = {};
	struct dr_devx_flow_fte_attr fte_attr = {};
	uint32_t i;
	int ret;

	switch (dmn->type) {
	case MLX5DV_DR_DOMAIN_TYPE_FDB:
		ft_attr.type = FS_FT_FDB;
		ft_attr.level = dmn->info.caps.max_ft_level - 1;
		break;
	case MLX5DV_DR_DOMAIN_TYPE_NIC_RX:
		ft_attr.type = FS_FT_NIC_RX;
		ft_attr.level = MLX5_MULTI_PATH_FT_MAX_LEVEL - 1;
		break;
	default:
		errno = EOPNOTSUPP;
		return errno;
	}

	fte_attr.dest_arr = calloc(num_dest, sizeof(struct dr_devx_flow_dest_info));
	if (!fte_attr.dest_arr) {
		errno = ENOMEM;
		return errno;
	}

	for (i = 0; i < num_dest; i++) {
		struct mlx5dv_dr_action *reformat_action;
		struct mlx5dv_dr_action *dest_action;

		switch (dests[i]->type) {
		case MLX5DV_DR_ACTION_DEST_REFORMAT:
			dest_action = dests[i]->dest_reformat->dest;
			reformat_action = dests[i]->dest_reformat->reformat;
			ft_attr.reformat_en = true;
			break;
		case MLX5DV_DR_ACTION_DEST:
			dest_action = dests[i]->dest;
			reformat_action = NULL;
			break;
		default:
			errno = EINVAL;
			goto clear_actions_list;
		}

		switch (dest_action->action_type) {
		case DR_ACTION_TYP_MISS:
		case DR_ACTION_TYP_VPORT:
		case DR_ACTION_TYP_QP:
		case DR_ACTION_TYP_CTR:
		case DR_ACTION_TYP_FT:
			if (dr_action_add_action_member(&action->dest_array.actions_list,
							dest_action))
				goto clear_actions_list;

			break;
		default:
			errno = EOPNOTSUPP;
			goto clear_actions_list;
		}

		if (reformat_action)
			if (dr_action_add_action_member(&action->dest_array.actions_list,
							reformat_action))
				goto clear_actions_list;

		if (dr_action_convert_to_fte_dest(dmn, dest_action,
						  reformat_action, &fte_attr))
			goto clear_actions_list;
	}

	action->dest_array.devx_tbl = dr_devx_create_always_hit_ft(dmn->ctx,
								   &ft_attr,
								   &fg_attr,
								   &fte_attr);
	if (!action->dest_array.devx_tbl)
		goto clear_actions_list;

	ret = dr_devx_query_flow_table(action->dest_array.devx_tbl->ft_dvo,
				       ft_attr.type,
				       &action->dest_array.rx_icm_addr,
				       &action->dest_array.tx_icm_addr);
	if (ret)
		goto destroy_devx_tbl;

	free(fte_attr.dest_arr);
	return 0;

destroy_devx_tbl:
	dr_devx_destroy_always_hit_ft(action->dest_array.devx_tbl);
clear_actions_list:
	dr_action_remove_action_members(&action->dest_array.actions_list);

	free(fte_attr.dest_arr);
	return errno;
}

struct mlx5dv_dr_action *
mlx5dv_dr_action_create_dest_array(struct mlx5dv_dr_domain *dmn,
				   size_t num_dest,
				   struct mlx5dv_dr_action_dest_attr *dests[])
{
	struct mlx5dv_dr_action *action;

	if (num_dest <= 1) {
		errno = EINVAL;
		return NULL;
	}

	atomic_fetch_add(&dmn->refcount, 1);

	action = dr_action_create_generic(DR_ACTION_TYP_DEST_ARRAY);
	if (!action)
		goto dec_ref;

	action->dest_array.dmn = dmn;
	list_head_init(&action->dest_array.actions_list);

	if (dr_action_create_dest_array_tbl(action, num_dest, dests))
		goto free_action;

	return action;

free_action:
	free(action);
dec_ref:
	atomic_fetch_sub(&dmn->refcount, 1);
	return NULL;
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
	case DR_ACTION_TYP_METER:
		mlx5dv_devx_obj_destroy(action->meter.devx_obj);
		atomic_fetch_sub(&action->meter.next_ft->refcount, 1);
		break;
	case DR_ACTION_TYP_SAMPLER:
		if (action->sampler.sampler_restore) {
			dr_action_destroy_sampler(action->sampler.sampler_restore);
			dr_action_destroy_sampler_restore_tbl(action->sampler.restore_tbl);
		}
		dr_action_destroy_sampler(action->sampler.sampler_default);
		dr_action_destroy_sampler_term_tbl(action->sampler.term_tbl);
		atomic_fetch_sub(&action->sampler.dmn->refcount, 1);
		break;
	case DR_ACTION_TYP_DEST_ARRAY:
		dr_devx_destroy_always_hit_ft(action->dest_array.devx_tbl);
		dr_action_remove_action_members(&action->dest_array.actions_list);
		atomic_fetch_sub(&action->dest_array.dmn->refcount, 1);
		break;
	default:
		break;
	}

	free(action);
	return 0;
}
