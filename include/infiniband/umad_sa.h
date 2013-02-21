/*
 * Copyright (c) 2004 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Voltaire, Inc.  All rights reserved.
 * Copyright (c) 2006, 2010 Intel Corporation.  All rights reserved.
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
#ifndef _UMAD_SA_H
#define _UMAD_SA_H

#include <infiniband/umad_types.h>

#ifdef __cplusplus
#  define BEGIN_C_DECLS extern "C" {
#  define END_C_DECLS   }
#else				/* !__cplusplus */
#  define BEGIN_C_DECLS
#  define END_C_DECLS
#endif				/* __cplusplus */

BEGIN_C_DECLS

/* SA specific methods */
enum {
	UMAD_SA_CLASS_VERSION		= 2,	/* IB spec version 1.1/1.2 */

	UMAD_SA_METHOD_GET_TABLE	= 0x12,
	UMAD_SA_METHOD_GET_TABLE_RESP	= 0x92,
	UMAD_SA_METHOD_DELETE		= 0x15,
	UMAD_SA_METHOD_DELETE_RESP	= 0x95,
	UMAD_SA_METHOD_GET_MULTI	= 0x14,
	UMAD_SA_METHOD_GET_MULTI_RESP	= 0x94,
	UMAD_SA_METHOD_GET_TRACE_TABLE	= 0x13
};

enum {
	UMAD_SA_STATUS_SUCCESS		= 0,
	UMAD_SA_STATUS_NO_RESOURCES	= 1,
	UMAD_SA_STATUS_REQ_INVALID	= 2,
	UMAD_SA_STATUS_NO_RECORDS	= 3,
	UMAD_SA_STATUS_TOO_MANY_RECORDS	= 4,
	UMAD_SA_STATUS_INVALID_GID	= 5,
	UMAD_SA_STATUS_INSUF_COMPS	= 6,
	UMAD_SA_STATUS_REQ_DENIED	= 7
};

/* SA attributes */
enum {
	UMAD_SA_ATTR_NODE_REC		= 0x0011,
	UMAD_SA_ATTR_PORT_INFO_REC	= 0x0012,
	UMAD_SA_ATTR_SLVL_REC		= 0x0013,
	UMAD_SA_ATTR_SWITCH_INFO_REC	= 0x0014,
	UMAD_SA_ATTR_LINEAR_FT_REC	= 0x0015,
	UMAD_SA_ATTR_RANDOM_FT_REC	= 0x0016,
	UMAD_SA_ATTR_MCAST_FT_REC	= 0x0017,
	UMAD_SA_ATTR_SM_INFO_REC	= 0x0018,
	UMAD_SA_ATTR_INFORM_INFO_REC	= 0x00F3,
	UMAD_SA_ATTR_LINK_REC		= 0x0020,
	UMAD_SA_ATTR_GUID_INFO_REC	= 0x0030,
	UMAD_SA_ATTR_SERVICE_REC	= 0x0031,
	UMAD_SA_ATTR_PKEY_TABLE_REC	= 0x0033,
	UMAD_SA_ATTR_PATH_REC		= 0x0035,
	UMAD_SA_ATTR_VL_ARB_REC		= 0x0036,
	UMAD_SA_ATTR_MCMEMBER_REC	= 0x0038,
	UMAD_SA_ATTR_TRACE_REC		= 0x0039,
	UMAD_SA_ATTR_MULTI_PATH_REC	= 0x003A,
	UMAD_SA_ATTR_SERVICE_ASSOC_REC	= 0x003B
};

enum {
	UMAD_LEN_SA_DATA		= 200
};

/*
 *  sm_key is not aligned on an 8-byte boundary, so is defined as a byte array
 */
struct umad_sa_packet {
	struct umad_hdr		mad_hdr;
	struct umad_rmpp_hdr	rmpp_hdr;
	uint8_t			sm_key[8]; /* network-byte order */
	be16_t			attr_offset;
	be16_t			reserved;
	be64_t			comp_mask;
	uint8_t 		data[UMAD_LEN_SA_DATA]; /* network-byte order */
};

END_C_DECLS
#endif				/* _UMAD_SA_H */
