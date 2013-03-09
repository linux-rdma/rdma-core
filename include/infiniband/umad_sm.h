/*
 * Copyright (c) 2004 Mellanox Technologies Ltd.  All rights reserved.
 * Copyright (c) 2004 Infinicon Corporation.  All rights reserved.
 * Copyright (c) 2004 Intel Corporation.  All rights reserved.
 * Copyright (c) 2004 Topspin Corporation.  All rights reserved.
 * Copyright (c) 2004 Voltaire Corporation.  All rights reserved.
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

#ifndef _UMAD_SM_H
#define _UMAD_SM_H

#include <infiniband/umad_types.h>

#ifdef __cplusplus
#  define BEGIN_C_DECLS extern "C" {
#  define END_C_DECLS   }
#else				/* !__cplusplus */
#  define BEGIN_C_DECLS
#  define END_C_DECLS
#endif				/* __cplusplus */

BEGIN_C_DECLS

enum {
	UMAD_SMP_DIRECTION		= 0x8000,
};

/* Subnet management attributes */
enum {
	UMAD_SMP_ATTR_NODE_DESC			= 0x0010,
	UMAD_SMP_ATTR_NODE_INFO			= 0x0011,
	UMAD_SMP_ATTR_SWITCH_INFO		= 0x0012,
	UMAD_SMP_ATTR_GUID_INFO			= 0x0014,
	UMAD_SMP_ATTR_PORT_INFO			= 0x0015,
	UMAD_SMP_ATTR_PKEY_TABLE		= 0x0016,
	UMAD_SMP_ATTR_SLVL_TABLE		= 0x0017,
	UMAD_SMP_ATTR_VL_ARB_TABLE		= 0x0018,
	UMAD_SMP_ATTR_LINEAR_FT			= 0x0019,
	UMAD_SMP_ATTR_RANDOM_FT			= 0x001A,
	UMAD_SMP_ATTR_MCAST_FT			= 0x001B,
	UMAD_SMP_ATTR_LINK_SPD_WIDTH_TABLE	= 0x001C,
	UMAD_SMP_ATTR_VENDOR_MADS_TABLE		= 0x001D,
	UMAD_SMP_ATTR_HIERARCHY_INFO		= 0x001E,
	UMAD_SMP_ATTR_SM_INFO			= 0x0020,
	UMAD_SMP_ATTR_VENDOR_DIAG		= 0x0030,
	UMAD_SMP_ATTR_LED_INFO			= 0x0031,
	UMAD_SMP_ATTR_CABLE_INFO		= 0x0032,
	UMAD_SMP_ATTR_VENDOR_MASK		= 0xFF00
};

enum {
	UMAD_LEN_SMP_DATA		= 64,
	UMAD_SMP_MAX_HOPS		= 64
};

struct umad_smp {
	uint8_t	 base_version;
	uint8_t	 mgmt_class;
	uint8_t	 class_version;
	uint8_t	 method;
	be16_t   status;
	uint8_t  hop_ptr;
	uint8_t  hop_cnt;
	be64_t   tid;
	be16_t   attr_id;
	be16_t   resv;
	be32_t   attr_mod;
	be64_t   mkey;
	be16_t   dr_slid;
	be16_t   dr_dlid;
	uint8_t  reserved[28];
	uint8_t  data[UMAD_LEN_SMP_DATA];
	uint8_t  initial_path[UMAD_SMP_MAX_HOPS];
	uint8_t  return_path[UMAD_SMP_MAX_HOPS];
};

END_C_DECLS
#endif				/* _UMAD_SM_H */
