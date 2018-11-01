/*
 * srp-ib_types - discover SRP targets over IB
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2006 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2006 Mellanox Technologies Ltd.  All rights reserved.
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

#ifndef SRP_IB_TYPES_H
#define SRP_IB_TYPES_H

#include <endian.h>
#include <stdint.h>
#include <linux/types.h> /* __be16, __be32 and __be64 */
#include <infiniband/umad.h> /* union umad_gid */
#include <infiniband/umad_types.h>

#define SRP_INFORMINFO_LID_COMP		(1 << 1)
#define SRP_INFORMINFO_ISGENERIC_COMP	(1 << 4)
#define SRP_INFORMINFO_SUBSCRIBE_COMP	(1 << 5)
#define SRP_INFORMINFO_TRAPTYPE_COMP	(1 << 6)
#define SRP_INFORMINFO_TRAPNUM_COMP	(1 << 7)
#define SRP_INFORMINFO_QPN_COMP		(1 << 8)
#define SRP_INFORMINFO_PRODUCER_COMP	(1 << 12)

#define PACK_SUFFIX4 __attribute__((aligned(4))) __attribute__((packed))
#define PACK_SUFFIX __attribute__((packed))

/****d* IBA Base: Constants/MAD_BLOCK_SIZE
* NAME
*	MAD_BLOCK_SIZE
*
* DESCRIPTION
*	Size of a non-RMPP MAD datagram.
*
* SOURCE
*/
#define MAD_BLOCK_SIZE						256

static inline uint32_t ib_get_attr_size(const __be16 attr_offset)
{
	return( ((uint32_t)be16toh( attr_offset )) << 3 );
}

/************************************************************
* NAME
*	MAD_RMPP_HDR_SIZE
*
* DESCRIPTION
*	Size of an RMPP header, including the common MAD header.
*
* SOURCE
*/
enum {
  MAD_RMPP_HDR_SIZE = 36,
};

/****s* IBA Base: Types/struct ib_path_rec
* NAME
*	struct ib_path_rec
*
* DESCRIPTION
*	Path records encapsulate the properties of a given
*	route between two end-points on a subnet.
*
* SYNOPSIS
*
* NOTES
*	The role of this data structure is identical to the role of struct
*	ibv_path_record in libibverbs/sa.h.
*/
struct ib_path_rec {
	uint8_t		resv0[8];
	union umad_gid	dgid;
	union umad_gid	sgid;
	__be16		dlid;
	__be16		slid;
	__be32		hop_flow_raw;
	uint8_t		tclass;
	uint8_t		reversible_numpath; /* reversible-7:7 num path-6:0 */
	__be16		pkey;
	__be16		sl;
	uint8_t		mtu;
	uint8_t		rate;
	uint8_t		pkt_life;
	uint8_t		preference;
	uint8_t		resv2[6];
};


/****f* IBA Base: Types/umad_init_new
* NAME
*	umad_init_new
*
* DESCRIPTION
*	Initialize UMAD common header.
*
* SYNOPSIS
*/
static inline void
umad_init_new(struct umad_hdr* const	p_mad,
	      const uint8_t mgmt_class,
	      const uint8_t class_ver,
	      const uint8_t method,
	      const __be64 trans_id,
	      const __be16 attr_id,
	      const __be32 attr_mod)
{
	p_mad->base_version = 1;
	p_mad->mgmt_class = mgmt_class;
	p_mad->class_version = class_ver;
	p_mad->method = method;
	p_mad->status = 0;
	p_mad->class_specific = 0;
	p_mad->tid = trans_id;
	p_mad->attr_id = attr_id;
	p_mad->resv = 0;
	p_mad->attr_mod = attr_mod;
}


struct ib_inform_info
{
	union umad_gid	gid;
	__be16		lid_range_begin;
	__be16		lid_range_end;
	__be16		reserved1;
	uint8_t		is_generic;
	uint8_t		subscribe;
	__be16		trap_type;
	union _inform_g_or_v
	{
		struct _inform_generic
		{
			__be16		trap_num;
			__be32		qpn_resp_time_val;
			uint8_t 	reserved2;
			uint8_t		node_type_msb;
			__be16		node_type_lsb;
		} PACK_SUFFIX generic;

		struct _inform_vend
		{
			__be16		dev_id;
			__be32		qpn_resp_time_val;
			uint8_t		reserved2;
			uint8_t		vendor_id_msb;
			__be16		vendor_id_lsb;
		} PACK_SUFFIX vend;

	}	PACK_SUFFIX g_or_v;

} PACK_SUFFIX4;

struct ib_mad_notice_attr		// Total Size calc  Accumulated
{
	union
	{
		uint8_t	generic_type;	// 1		1

		struct _notice_generic
		{
			uint8_t		generic_type;
			uint8_t		prod_type_msb;
			__be16		prod_type_lsb;
			__be16		trap_num;
		} generic;

		struct _notice_vend
		{
			uint8_t		generic_type;
			uint8_t		vend_id_msb;
			__be16		vend_id_lsb;
			__be16		dev_id;
		} vend;
	};

	__be16 issuer_lid;		// 2		8

	union				// 54		64
	{
		__be16		toggle_count;		// 2		10
		struct _raw_data
		{
			__be16  toggle_count;
			uint8_t	details[54];
		} raw_data;

		struct _ntc_64_67
		{
			__be16		toggle_count;
			uint8_t		res[6];
			union umad_gid	gid;	// the Node or Multicast Group that came in/out
		} ntc_64_67;

		struct _ntc_144 {
			__be16		toggle_count;
			__be16		pad1;
			__be16		lid;		// lid where capability mask changed
			__be16		pad2;
			__be32		new_cap_mask;	// new capability mask
		} ntc_144;
	};

	union umad_gid			issuer_gid;	// 16		80

};

/****f* IBA Base: Types/ib_gid_get_guid
* NAME
*	ib_gid_get_guid
*
* DESCRIPTION
*	Gets the guid from a GID.
*
* SYNOPSIS
*/
static inline __be64 ib_gid_get_guid(const union umad_gid *const p_gid)
{
	return p_gid->global.interface_id;
}

#endif
