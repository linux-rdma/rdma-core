/*
 * Copyright (c) 2017 Mellanox Technologies LTD. All rights reserved.
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
 *
 */
#ifndef _UMAD_SA_MCM_H
#define _UMAD_SA_MCM_H

#include <infiniband/umad_types.h>
#include <infiniband/umad_sa.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Component mask bits for MCMemberRecord */
enum {
	UMAD_SA_MCM_COMP_MASK_MGID		= (1ULL << 0),
	UMAD_SA_MCM_COMP_MASK_PORT_GID		= (1ULL << 1),
	UMAD_SA_MCM_COMP_MASK_QKEY		= (1ULL << 2),
	UMAD_SA_MCM_COMP_MASK_MLID		= (1ULL << 3),
	UMAD_SA_MCM_COMP_MASK_MTU_SEL		= (1ULL << 4),
	UMAD_SA_MCM_COMP_MASK_MTU		= (1ULL << 5),
	UMAD_SA_MCM_COMP_MASK_TCLASS		= (1ULL << 6),
	UMAD_SA_MCM_COMP_MASK_PKEY		= (1ULL << 7),
	UMAD_SA_MCM_COMP_MASK_RATE_SEL		= (1ULL << 8),
	UMAD_SA_MCM_COMP_MASK_RATE		= (1ULL << 9),
	UMAD_SA_MCM_COMP_MASK_LIFE_TIME_SEL	= (1ULL << 10),
	UMAD_SA_MCM_COMP_MASK_LIFE_TIME		= (1ULL << 11),
	UMAD_SA_MCM_COMP_MASK_SL		= (1ULL << 12),
	UMAD_SA_MCM_COMP_MASK_FLOW_LABEL	= (1ULL << 13),
	UMAD_SA_MCM_COMP_MASK_HOP_LIMIT		= (1ULL << 14),
	UMAD_SA_MCM_COMP_MASK_SCOPE		= (1ULL << 15),
	UMAD_SA_MCM_COMP_MASK_JOIN_STATE	= (1ULL << 16),
	UMAD_SA_MCM_COMP_MASK_PROXY_JOIN	= (1ULL << 17)
};

enum {
	UMAD_SA_MCM_JOIN_STATE_FULL_MEMBER	= (1 << 0),
	UMAD_SA_MCM_JOIN_STATE_NON_MEMBER	= (1 << 1),
	UMAD_SA_MCM_JOIN_STATE_SEND_ONLY_NON_MEMBER = (1 << 2),
	UMAD_SA_MCM_JOIN_STATE_SEND_ONLY_FULL_MEMBER = (1 << 3)
};

enum {
	UMAD_SA_MCM_ADDR_SCOPE_LINK_LOCAL = 0x2,
	UMAD_SA_MCM_ADDR_SCOPE_SITE_LOCAL = 0x5,
	UMAD_SA_MCM_ADDR_SCOPE_ORG_LOCAL  = 0x8,
	UMAD_SA_MCM_ADDR_SCOPE_GLOBAL     = 0xE,
};

struct umad_sa_mcmember_record {
	uint8_t mgid[16];	/* network-byte order */
	uint8_t portgid[16];	/* network-byte order */
	__be32	qkey;
	__be16	mlid;
	uint8_t mtu;		/* 2 bit selector included */
	uint8_t tclass;
	__be16	pkey;
	uint8_t rate;		/* 2 bit selector included */
	uint8_t pkt_life;	/* 2 bit selector included */
	__be32	sl_flow_hop;	/* SL: 4 bits, FlowLabel: 20 bits, */
				/* HopLimit: 8 bits */
	uint8_t scope_state;	/* Scope: 4 bits, JoinState: 4 bits */
	uint8_t proxy_join;	/* ProxyJoin: 1 bit (computed by SA) */
	uint8_t reserved[2];
	uint8_t pad[4];		/* SA records are multiple of 8 bytes */
};

static inline void
umad_sa_mcm_get_sl_flow_hop(__be32 sl_flow_hop, uint8_t * const p_sl,
			    uint32_t * const p_flow_lbl, uint8_t * const p_hop)
{
	uint32_t tmp;

	tmp = ntohl(sl_flow_hop);
	if (p_hop)
		*p_hop = (uint8_t) tmp;

	tmp >>= 8;
	if (p_flow_lbl)
		*p_flow_lbl = (uint32_t) (tmp & 0xfffff);

	tmp >>= 20;
	if (p_sl)
		*p_sl = (uint8_t) tmp;
}

static inline __be32
umad_sa_mcm_set_sl_flow_hop(uint8_t sl, uint32_t flow_label, uint8_t hop_limit)
{
	uint32_t tmp;

	tmp = (sl << 28) | ((flow_label & 0xfffff) << 8) | hop_limit;
	return htonl(tmp);
}

static inline void
umad_sa_mcm_get_scope_state(const uint8_t scope_state, uint8_t * const p_scope,
			    uint8_t * const p_state)
{
	uint8_t tmp_scope_state;

	if (p_state)
		*p_state = (uint8_t) (scope_state & 0x0f);

	tmp_scope_state = scope_state >> 4;

	if (p_scope)
		*p_scope = (uint8_t) (tmp_scope_state & 0x0f);
}

static inline uint8_t
umad_sa_mcm_set_scope_state(const uint8_t scope, const uint8_t state)
{
	uint8_t scope_state;

	scope_state = scope;
	scope_state = scope_state << 4;
	scope_state = scope_state | state;
	return scope_state;
}

static inline void
umad_sa_mcm_set_join_state(struct umad_sa_mcmember_record *p_mc_rec,
			   const uint8_t state)
{
	/* keep the scope as it is */
	p_mc_rec->scope_state = (p_mc_rec->scope_state & 0xf0) | (0x0f & state);
}

static inline int
umad_sa_mcm_get_proxy_join(struct umad_sa_mcmember_record *p_mc_rec)
{
	return ((p_mc_rec->proxy_join & 0x80) == 0x80);
}

#ifdef __cplusplus
}
#endif
#endif				/* _UMAD_SA_MCM_H */
