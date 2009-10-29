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

#define IB_ACM_FLAGS_CM              (1<<0)
#define IB_ACM_FLAGS_PRIMARY         (1<<1)
#define IB_ACM_FLAGS_ALTERNATE       (1<<2)
#define IB_ACM_FLAGS_OUTBOUND        (1<<3)
#define IB_ACM_FLAGS_INBOUND         (1<<4)
#define IB_ACM_FLAGS_INBOUND_REVERSE (1<<5)
#define IB_ACM_FLAGS_BIDIRECTIONAL   (IB_ACM_FLAGS_OUTBOUND | IB_ACM_FLAGS_INBOUND_REVERSE)

struct ib_acm_path_data
{
	uint32_t              flags;
	uint32_t              reserved;
	struct ib_path_record path;
};

struct ib_acm_cm_data
{
	uint8_t  init_depth;
	uint8_t  resp_resources;
	uint8_t  reserved2;
	uint8_t  cm_data_length;
	uint32_t cm_data[15];
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
	struct ib_acm_path_data **paths, int *count,
	struct ib_acm_cm_data *data);

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
	struct ib_acm_path_data **paths, int *count,
	struct ib_acm_cm_data *data);

#define ib_acm_free_paths(paths) free(paths)

#define IB_ACM_FLAGS_QUERY_SA   (1<<31)

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
int ib_acm_resolve_path(struct ib_path_record *path, uint32_t flags);

#ifdef __cplusplus
}
#endif

#endif /* IB_ACM_H */
