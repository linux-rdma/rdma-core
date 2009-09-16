/*
 * Copyright (c) 2009 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under the OpenFabrics.org BSD license
 * below:
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
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if !defined(IB_ACM_H)
#define IB_ACM_H

#include <infiniband/verbs.h>

#if defined(_WIN32)
#define LIB_EXPORT __declspec(dllexport)
#else
#define LIB_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct ib_acm_dev_addr
{
	uint64_t guid;
	uint16_t pkey_index;
	uint8_t  port_num;
	uint8_t  reserved[5];
};

struct ib_acm_resolve_data
{
	uint32_t reserved1;
	uint8_t  init_depth;
	uint8_t	 resp_resources;
	uint8_t  packet_lifetime;
	uint8_t  mtu;
	uint8_t  reserved2[8];
};

/**
 * ib_acm_resolve_name - Resolve path data between the specified names.
 * Description:
 *   Discover path information, including identifying the local device,
 *   between the given the source and destination names.
 * Notes:
 *   The source and destination names should match entries in acm_addr.cfg
 *   configuration files on their respective systems.  Typically, the
 *   source and destination names will refer to system host names
 *   assigned to an Infiniband port.
 */
LIB_EXPORT
int ib_acm_resolve_name(char *src, char *dest,
	struct ib_acm_dev_addr *dev_addr, struct ibv_ah_attr *ah,
	struct ib_acm_resolve_data *data);

/**
 * ib_acm_resolve_ip - Resolve path data between the specified addresses.
 * Description:
 *   Discover path information, including identifying the local device,
 *   between the given the source and destination addresses.
 * Notes:
 *   The source and destination addresses should match entries in acm_addr.cfg
 *   configuration files on their respective systems.  Typically, the
 *   source and destination addresses will refer to IP addresses assigned
 *   to an IPoIB instance.
 */
LIB_EXPORT
int ib_acm_resolve_ip(struct sockaddr *src, struct sockaddr *dest,
	struct ib_acm_dev_addr *dev_addr, struct ibv_ah_attr *ah,
	struct ib_acm_resolve_data *data);


#define IB_PATH_RECORD_REVERSIBLE 0x80

struct ib_path_record
{
	uint64_t        service_id;
	union ibv_gid   dgid;
	union ibv_gid   sgid;
	uint16_t        dlid;
	uint16_t        slid;
	uint32_t        flowlabel_hoplimit; /* resv-31:28 flow label-27:8 hop limit-7:0*/
	uint8_t         tclass;
	uint8_t         reversible_numpath; /* reversible-7:7 num path-6:0 */
	uint16_t        pkey;
	uint16_t        qosclass_sl;        /* qos class-15:4 sl-3:0 */
	uint8_t         mtu;                /* mtu selector-7:6 mtu-5:0 */
	uint8_t         rate;               /* rate selector-7:6 rate-5:0 */
	uint8_t         packetlifetime;     /* lifetime selector-7:6 lifetime-5:0 */
	uint8_t         preference;
	uint8_t         reserved[6];
};

/**
 * ib_acm_resolve_path - Resolve path data meeting specified restrictions
 * Description:
 *   Discover path information using the provided path record to
 *   restrict the discovery.
 * Notes:
 *   Uses the provided path record as input into an query for path
 *   information.  If successful, fills in any missing information.  The
 *   caller must provide at least the source and destination LIDs as input.
 */
LIB_EXPORT
int ib_acm_resolve_path(struct ib_path_record *path);

/**
 * ib_acm_query_path - Resolve path data meeting specified restrictions
 * Description:
 *   Queries the IB SA for a path record using the provided path record to
 *   restrict the query.
 * Notes:
 *   Uses the provided path record as input into an SA query for path
 *   information.  If successful, fills in any missing information.  The
 *   caller must provide at least the source and destination LIDs as input.
 *   Use of this call always results in sending a query to the IB SA.
 */
LIB_EXPORT
int ib_acm_query_path(struct ib_path_record *path);

/**
 * ib_acm_convert_to_path - Convert resolved path data to a path record
 * Description:
 *   Converts path information returned from resolving a host name or address
 *   to the format of an IB path record.
 */
LIB_EXPORT
int ib_acm_convert_to_path(struct ib_acm_dev_addr *dev_addr,
	struct ibv_ah_attr *ah, struct ib_acm_resolve_data *data,
	struct ib_path_record *path);

#ifdef __cplusplus
}
#endif

#endif /* IB_ACM_H */
