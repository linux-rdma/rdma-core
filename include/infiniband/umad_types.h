/*
 * Copyright (c) 2004 Mellanox Technologies Ltd.  All rights reserved.
 * Copyright (c) 2004 Infinicon Corporation.  All rights reserved.
 * Copyright (c) 2004, 2010 Intel Corporation.  All rights reserved.
 * Copyright (c) 2004 Topspin Corporation.  All rights reserved.
 * Copyright (c) 2004-2006 Voltaire Corporation.  All rights reserved.
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
#ifndef _UMAD_TYPES_H
#define _UMAD_TYPES_H

#include <stdint.h>
#include <infiniband/umad.h>

#ifdef __cplusplus
#  define BEGIN_C_DECLS extern "C" {
#  define END_C_DECLS   }
#else				/* !__cplusplus */
#  define BEGIN_C_DECLS
#  define END_C_DECLS
#endif				/* __cplusplus */

BEGIN_C_DECLS

#define UMAD_BASE_VERSION		1

/* Management classes */
enum {
	UMAD_CLASS_SUBN_LID_ROUTED	= 0x01,
	UMAD_CLASS_SUBN_DIRECTED_ROUTE	= 0x81,
	UMAD_CLASS_SUBN_ADM		= 0x03,
	UMAD_CLASS_PERF_MGMT		= 0x04,
	UMAD_CLASS_BM			= 0x05,
	UMAD_CLASS_DEVICE_MGMT		= 0x06,
	UMAD_CLASS_CM			= 0x07,
	UMAD_CLASS_SNMP			= 0x08,
	UMAD_CLASS_VENDOR_RANGE1_START	= 0x09,
	UMAD_CLASS_VENDOR_RANGE1_END	= 0x0F,
	UMAD_CLASS_DEVICE_ADM		= 0x10,
	UMAD_CLASS_BOOT_MGMT		= 0x11,
	UMAD_CLASS_BIS			= 0x12,
	UMAD_CLASS_CONG_MGMT		= 0x21,
	UMAD_CLASS_VENDOR_RANGE2_START	= 0x30,
	UMAD_CLASS_VENDOR_RANGE2_END	= 0x4F
};

/* Management methods */
enum {
	UMAD_METHOD_GET			= 0x01,
	UMAD_METHOD_SET			= 0x02,
	UMAD_METHOD_GET_RESP		= 0x81,
	UMAD_METHOD_SEND		= 0x03,
	UMAD_METHOD_TRAP		= 0x05,
	UMAD_METHOD_REPORT		= 0x06,
	UMAD_METHOD_REPORT_RESP		= 0x86,
	UMAD_METHOD_TRAP_REPRESS	= 0x07,
	UMAD_METHOD_RESP		= 0x80
};

enum {
	UMAD_STATUS_SUCCESS  = 0x0000,
	UMAD_STATUS_BUSY     = 0x0001,
	UMAD_STATUS_REDIRECT = 0x0002,

	/* Invalid fields, bits 2-4 */
	UMAD_STATUS_BAD_VERSION          = (1 << 2),
	UMAD_STATUS_METHOD_NOT_SUPPORTED = (2 << 2),
	UMAD_STATUS_ATTR_NOT_SUPPORTED   = (3 << 2),
	UMAD_STATUS_INVALID_ATTR_VALUE   = (7 << 2),

	UMAD_STATUS_CLASS_MASK = 0xFF00
};

/* Attributes common to multiple classes */
enum {
	UMAD_ATTR_CLASS_PORT_INFO	= 0x0001,
	UMAD_ATTR_NOTICE		= 0x0002,
	UMAD_ATTR_INFORM_INFO		= 0x0003
};

/* RMPP information */
#define UMAD_RMPP_VERSION		1

enum {
	UMAD_LEN_DATA			= 232,
	UMAD_LEN_RMPP_DATA		= 220,
	UMAD_LEN_VENDOR_DATA		= 216,
};

struct umad_hdr {
	uint8_t	 base_version;
	uint8_t	 mgmt_class;
	uint8_t	 class_version;
	uint8_t	 method;
	uint16_t status;
	be16_t   class_specific;
	be64_t   tid;
	be16_t   attr_id;
	be16_t   resv;
	be32_t   attr_mod;
};

struct umad_rmpp_hdr {
	uint8_t	 rmpp_version;
	uint8_t	 rmpp_type;
	uint8_t	 rmpp_rtime_flags;
	uint8_t	 rmpp_status;
	be32_t   seg_num;
	be32_t   paylen_newwin;
};

struct umad_packet {
	struct umad_hdr		mad_hdr;
	uint8_t			data[UMAD_LEN_DATA]; /* network-byte order */
};

struct umad_rmpp_packet {
	struct umad_hdr		mad_hdr;
	struct umad_rmpp_hdr	rmpp_hdr;
	uint8_t			data[UMAD_LEN_RMPP_DATA]; /* network-byte order */
};

struct umad_vendor_packet {
	struct umad_hdr		mad_hdr;
	struct umad_rmpp_hdr	rmpp_hdr;
	uint8_t			reserved;
	uint8_t			oui[3];	/* network-byte order */
	uint8_t			data[UMAD_LEN_VENDOR_DATA]; /* network-byte order */
};

enum {
	UMAD_OPENIB_OUI		= 0x001405
};

END_C_DECLS
#endif				/* _UMAD_TYPES_H */
