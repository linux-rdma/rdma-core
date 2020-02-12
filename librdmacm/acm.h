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

#if !defined(ACM_H)
#define ACM_H

#include <infiniband/verbs.h>
#include <infiniband/sa.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ACM_VERSION             1

#define ACM_OP_MASK             0x0F
#define ACM_OP_RESOLVE          0x01
#define ACM_OP_PERF_QUERY       0x02
#define ACM_OP_EP_QUERY         0x03
#define ACM_OP_ACK              0x80

#define ACM_STATUS_SUCCESS      0
#define ACM_STATUS_ENOMEM       1
#define ACM_STATUS_EINVAL       2
#define ACM_STATUS_ENODATA      3
#define ACM_STATUS_ENOTCONN     5
#define ACM_STATUS_ETIMEDOUT    6
#define ACM_STATUS_ESRCADDR     7
#define ACM_STATUS_ESRCTYPE     8
#define ACM_STATUS_EDESTADDR    9
#define ACM_STATUS_EDESTTYPE    10

#define ACM_FLAGS_QUERY_SA      (1<<31)
#define ACM_FLAGS_NODELAY	(1<<30)

#define ACM_MSG_HDR_LENGTH      16
#define ACM_MAX_ADDRESS         64
#define ACM_MSG_EP_LENGTH       72
#define ACM_MAX_PROV_NAME       64
/*
 * Support up to 6 path records (primary and alternate CM paths,
 * inbound and outbound primary and alternate data paths), plus CM data.
 */
#define ACM_MSG_DATA_LENGTH     (ACM_MSG_EP_LENGTH * 8)

#define src_out     data[0]
#define src_index   data[1]
#define dst_index   data[2]

struct acm_hdr {
	uint8_t                 version;
	uint8_t                 opcode;
	uint8_t                 status;
	uint8_t		        data[3];
	uint16_t                length;
	uint64_t                tid;
};

#define ACM_EP_INFO_NAME        0x0001
#define ACM_EP_INFO_ADDRESS_IP  0x0002
#define ACM_EP_INFO_ADDRESS_IP6 0x0003
#define ACM_EP_INFO_PATH        0x0010

union acm_ep_info {
	uint8_t                 addr[ACM_MAX_ADDRESS];
	uint8_t                 name[ACM_MAX_ADDRESS];
	struct ibv_path_record  path;
};

#define ACM_EP_FLAG_SOURCE      (1<<0)
#define ACM_EP_FLAG_DEST        (1<<1)

struct acm_ep_addr_data {
	uint32_t                flags;
	uint16_t                type;
	uint16_t                reserved;
	union acm_ep_info       info;
};

/*
 * Resolve messages with the opcode set to ACM_OP_RESOLVE are only
 * used to communicate with the local ib_acm service.  Message fields
 * in this case are not byte swapped, but note that the acm_ep_info
 * data is in network order.
 */
struct acm_resolve_msg {
	struct acm_hdr          hdr;
	struct acm_ep_addr_data data[0];
};

enum {
	ACM_CNTR_ERROR,
	ACM_CNTR_RESOLVE,
	ACM_CNTR_NODATA,
	ACM_CNTR_ADDR_QUERY,
	ACM_CNTR_ADDR_CACHE,
	ACM_CNTR_ROUTE_QUERY,
	ACM_CNTR_ROUTE_CACHE,
	ACM_MAX_COUNTER
};

/*
 * Performance messages are sent/received in network byte order.
 */
struct acm_perf_msg {
	struct acm_hdr          hdr;
	uint64_t                data[0];
};

/*
 * Endpoint query messages are sent/received in network byte order.
 */
struct acm_ep_config_data {
	uint64_t                dev_guid;
	uint8_t                 port_num;
	uint8_t			phys_port_cnt;
	uint8_t                 rsvd[2];
	uint16_t                pkey;
	uint16_t                addr_cnt;
	uint8_t                 prov_name[ACM_MAX_PROV_NAME];
	union acm_ep_info       addrs[0];
};

struct acm_ep_query_msg {
	struct acm_hdr             hdr;
	struct acm_ep_config_data  data[0];
};

struct acm_msg {
	struct acm_hdr                  hdr;
	union{
		uint8_t                 data[ACM_MSG_DATA_LENGTH];
		struct acm_ep_addr_data resolve_data[0];
		uint64_t                perf_data[0];
		struct acm_ep_config_data ep_data[0];
	};
};

#ifdef __cplusplus
}
#endif

#endif /* ACM_H */
