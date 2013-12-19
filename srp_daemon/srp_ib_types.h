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

#include <netinet/in.h>

#define SRP_INFORMINFO_LID_COMP		(1 << 1)
#define SRP_INFORMINFO_ISGENERIC_COMP	(1 << 4)
#define SRP_INFORMINFO_SUBSCRIBE_COMP	(1 << 5)
#define SRP_INFORMINFO_TRAPTYPE_COMP	(1 << 6)
#define SRP_INFORMINFO_TRAPNUM_COMP	(1 << 7)
#define SRP_INFORMINFO_QPN_COMP		(1 << 8)
#define SRP_INFORMINFO_PRODUCER_COMP	(1 << 12)

#ifndef PACK_SUFFIX
#define PACK_SUFFIX __attribute__((packed))
#endif

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

/****d* IBA Base: Types/ib_net16_t
* NAME
*	ib_net16_t
*
* DESCRIPTION
*	Defines the network ordered type for 16-bit values.
*
* SOURCE
*/
typedef uint16_t	ib_net16_t;
/**********/
/****d* IBA Base: Types/ib_net32_t
* NAME
*	ib_net32_t
*
* DESCRIPTION
*	Defines the network ordered type for 32-bit values.
*
* SOURCE
*/
typedef uint32_t	ib_net32_t;
/**********/
/****d* IBA Base: Types/ib_net64_t
* NAME
*	ib_net64_t
*
* DESCRIPTION
*	Defines the network ordered type for 64-bit values.
*
* SOURCE
*/
typedef uint64_t	ib_net64_t;

typedef ib_net64_t		ib_gid_prefix_t;

/****s* IBA Base: Types/ib_sa_mad_t
* NAME
*	ib_sa_mad_t
*
* DESCRIPTION
*	IBA defined SA MAD format. (15.2.1)
*
* SYNOPSIS
*/
#define IB_SA_DATA_SIZE 200

typedef struct _ib_sa_mad
{
	uint8_t					base_ver;
	uint8_t					mgmt_class;
	uint8_t					class_ver;
	uint8_t					method;
	ib_net16_t				status;
	ib_net16_t				resv;
	ib_net64_t				trans_id;
	ib_net16_t				attr_id;
	ib_net16_t				resv1;
	ib_net32_t				attr_mod;

	uint8_t					rmpp_version;
	uint8_t					rmpp_type;
	uint8_t					rmpp_flags;
	uint8_t					rmpp_status;

	ib_net32_t				seg_num;
	ib_net32_t				paylen_newwin;

	ib_net64_t				sm_key;

	ib_net16_t				attr_offset;
	ib_net16_t				resv3;

	ib_net64_t				comp_mask;

	uint8_t					data[IB_SA_DATA_SIZE];
}	PACK_SUFFIX ib_sa_mad_t;

typedef union _ib_gid
{
	uint8_t					raw[16];
	struct _ib_gid_unicast
	{
		ib_gid_prefix_t		prefix;
		ib_net64_t			interface_id;

	} PACK_SUFFIX unicast;

	struct _ib_gid_multicast
	{
		uint8_t				header[2];
		uint8_t				raw_group_id[14];

	} PACK_SUFFIX multicast;

}	PACK_SUFFIX ib_gid_t;

static inline uint32_t ib_get_attr_size(const ib_net16_t attr_offset)
{
	return( ((uint32_t)ntohs( attr_offset )) << 3 );
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

/****s* IBA Base: Types/ib_path_rec_t
* NAME
*	ib_path_rec_t
*
* DESCRIPTION
*	Path records encapsulate the properties of a given
*	route between two end-points on a subnet.
*
* SYNOPSIS
*/
typedef struct _ib_path_rec
{
	uint8_t					resv0[8];
	ib_gid_t				dgid;
	ib_gid_t				sgid;
	ib_net16_t				dlid;
	ib_net16_t				slid;
	ib_net32_t				hop_flow_raw;
	uint8_t					tclass;
	uint8_t					num_path;
	ib_net16_t				pkey;
	ib_net16_t				sl;
	uint8_t					mtu;
	uint8_t					rate;
	uint8_t					pkt_life;
	uint8_t					preference;
	uint8_t					resv2[6];

}	PACK_SUFFIX ib_path_rec_t;


/****s* IBA Base: Types/ib_mad_t
* NAME
*	ib_mad_t
*
* DESCRIPTION
*	IBA defined MAD header (13.4.3)
*
* SYNOPSIS
*/
typedef struct _ib_mad
{
	uint8_t					base_ver;
	uint8_t					mgmt_class;
	uint8_t					class_ver;
	uint8_t					method;
	ib_net16_t				status;
	ib_net16_t				class_spec;
	ib_net64_t				trans_id;
	ib_net16_t				attr_id;
	ib_net16_t				resv;
	ib_net32_t				attr_mod;
}	PACK_SUFFIX ib_mad_t;

/****f* IBA Base: Types/ib_mad_init_new
* NAME
*	ib_mad_init_new
*
* DESCRIPTION
*	Initializes a MAD common header.
*
* SYNOPSIS
*/
static inline void
ib_mad_init_new(ib_mad_t* const		p_mad,
		const	uint8_t		mgmt_class,
		const	uint8_t		class_ver,
		const	uint8_t		method,
		const	ib_net64_t	trans_id,
		const	ib_net16_t	attr_id,
		const	ib_net32_t	attr_mod )
{
	p_mad->base_ver = 1;
	p_mad->mgmt_class = mgmt_class;
	p_mad->class_ver = class_ver;
	p_mad->method = method;
	p_mad->status = 0;
	p_mad->class_spec = 0;
	p_mad->trans_id = trans_id;
	p_mad->attr_id = attr_id;
	p_mad->resv = 0;
	p_mad->attr_mod = attr_mod;
}


typedef struct _ib_inform_info
{
  ib_gid_t				   gid;
  ib_net16_t				lid_range_begin;
  ib_net16_t				lid_range_end;
  ib_net16_t				reserved1;
  uint8_t					is_generic;
  uint8_t					subscribe;
  ib_net16_t				trap_type;
  union _inform_g_or_v
  {
	 struct _inform_generic
	 {
		ib_net16_t		trap_num;
		ib_net32_t		qpn_resp_time_val;
		uint8_t        		reserved2;
		uint8_t			node_type_msb;
		ib_net16_t		node_type_lsb;
	 } PACK_SUFFIX generic;

	 struct _inform_vend
	 {
		ib_net16_t		dev_id;
		ib_net32_t		qpn_resp_time_val;
      uint8_t        reserved2;
		uint8_t			vendor_id_msb;
		ib_net16_t		vendor_id_lsb;
	 } PACK_SUFFIX vend;

  }	PACK_SUFFIX g_or_v;

}	PACK_SUFFIX ib_inform_info_t;

typedef struct _ib_mad_notice_attr    // Total Size calc  Accumulated
{
  uint8_t				generic_type;    // 1                1

  union _notice_g_or_v
  {
	 struct _notice_generic            // 5                6
	 {
		uint8_t		prod_type_msb;
		ib_net16_t	prod_type_lsb;
		ib_net16_t	trap_num;
	 }	PACK_SUFFIX generic;

	 struct _notice_vend
	 {
		uint8_t		vend_id_msb;
		ib_net16_t	vend_id_lsb;
		ib_net16_t	dev_id;
	 }	PACK_SUFFIX vend;
  } g_or_v;

  ib_net16_t			issuer_lid;    // 2                 8
  ib_net16_t			toggle_count;  // 2                 10

  union _data_details               // 54                64
	{
	  struct _raw_data
	  {
		 uint8_t	details[54];
	  } PACK_SUFFIX raw_data;

	  struct _ntc_64_67
	  {
		 uint8_t    res[6];
		 ib_gid_t   gid;	// the Node or Multicast Group that came in/out
	  } PACK_SUFFIX ntc_64_67;

	  struct _ntc_128 {
		 ib_net16_t sw_lid; // the sw lid of which link state changed
	  } PACK_SUFFIX ntc_128;

	  struct _ntc_129_131 {
		 ib_net16_t    pad;
		 ib_net16_t    lid;		// lid and port number of the violation
		 uint8_t     port_num;
	  } PACK_SUFFIX ntc_129_131;

	  struct _ntc_144 {
		 ib_net16_t    pad1;
		 ib_net16_t    lid;		// lid where capability mask changed
		 ib_net16_t    pad2;
		 ib_net32_t    new_cap_mask; // new capability mask
	  } PACK_SUFFIX ntc_144;

	  struct _ntc_145 {
		 ib_net16_t    pad1;
		 ib_net16_t    lid;		// lid where sys guid changed
		 ib_net16_t    pad2;
		 ib_net64_t    new_sys_guid; // new system image guid
	  } PACK_SUFFIX ntc_145;

	  struct _ntc_256 {                       // total: 54
		 ib_net16_t    pad1;                   // 2
		 ib_net16_t    lid;                    // 2
		 ib_net16_t    pad2;                   // 2
		 uint8_t       method;                 // 1
		 uint8_t       pad3;                   // 1
		 ib_net16_t    attr_id;                // 2
		 ib_net32_t    attr_mod;               // 4
		 ib_net64_t    mkey;                   // 8
		 uint8_t       dr_slid;                // 1
		 uint8_t       dr_trunc_hop;           // 1
		 uint8_t       dr_rtn_path[30];        // 30
	  } PACK_SUFFIX ntc_256;

	  struct _ntc_257_258 // violation of p/q_key // 49
	  {
		 ib_net16_t    pad1;                   // 2
		 ib_net16_t    lid1;                   // 2
		 ib_net16_t    lid2;                   // 2
		 ib_net32_t    key;                    // 2
		 uint8_t       sl;                     // 1
		 ib_net32_t    qp1;                    // 4
		 ib_net32_t    qp2;                    // 4
		 ib_gid_t      gid1;                   // 16
		 ib_gid_t      gid2;                   // 16
	  } PACK_SUFFIX ntc_257_258;

	  struct _ntc_259 // p/q_key violation with sw info 53
	  {
		 ib_net16_t    data_valid;   // 2
		 ib_net16_t    lid1;         // 2
		 ib_net16_t    lid2;         // 2
		 ib_net32_t    key;          // 4
		 uint8_t       sl;           // 1
		 ib_net32_t    qp1;          // 4
		 uint8_t       qp2_msb;      // 1
		 ib_net16_t    qp2_lsb;      // 2
		 ib_gid_t      gid1;         // 16
		 ib_gid_t      gid2;         // 16
		 ib_net16_t    sw_lid;       // 2
		 uint8_t       port_no;      // 1
	  } PACK_SUFFIX ntc_259;

	} data_details;

  ib_gid_t			issuer_gid;    // 16          80

}	PACK_SUFFIX ib_mad_notice_attr_t;

/****f* IBA Base: Types/ib_gid_get_guid
* NAME
*	ib_gid_get_guid
*
* DESCRIPTION
*	Gets the guid from a GID.
*
* SYNOPSIS
*/
static inline ib_net64_t ib_gid_get_guid(const	ib_gid_t* const	p_gid)
{
	return( p_gid->unicast.interface_id );
}

#endif
