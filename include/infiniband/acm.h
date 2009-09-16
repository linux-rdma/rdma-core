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

#include <infiniband/ib_acm.h>

#define ACM_VERSION 1

#define ACM_OP_MASK     0x0F
#define ACM_OP_RESOLVE  0x01
#define ACM_OP_QUERY    0x02
//#define ACM_OP_CM       0x03
//#define ACM_OP_ACK_REQ  0x40 /* optional ack is required */
#define ACM_OP_ACK      0x80

#define ACM_STATUS_SUCCESS         0
#define ACM_STATUS_ENOMEM          1
#define ACM_STATUS_EINVAL          2
#define ACM_STATUS_ENODATA         3
#define ACM_STATUS_ENOTCONN        5
#define ACM_STATUS_ETIMEDOUT       6
#define ACM_STATUS_ESRCADDR        7
#define ACM_STATUS_ESRCTYPE        8
#define ACM_STATUS_EDESTADDR       9
#define ACM_STATUS_EDESTTYPE      10

struct acm_hdr
{
	uint8_t  version;
	uint8_t  opcode;
	uint8_t  status;
	uint8_t  param;
	uint8_t  dest_type;
	uint8_t  src_type;
	uint8_t  reserved[2];
	uint64_t tid;
};

#define ACM_EP_TYPE_NAME        0x01
#define ACM_EP_TYPE_ADDRESS_IP  0x02
#define ACM_EP_TYPE_ADDRESS_IP6 0x03
#define ACM_EP_TYPE_DEVICE      0x10
#define ACM_EP_TYPE_AV          0x20

#define ACM_MAX_ADDRESS  32

union acm_ep_addr
{
	uint8_t                addr[ACM_MAX_ADDRESS];
	uint8_t                name[ACM_MAX_ADDRESS];
	struct ib_acm_dev_addr dev;
	struct ibv_ah_attr     av;
};

struct acm_resolve_msg
{
	struct acm_hdr             hdr;
	union  acm_ep_addr         src;
	union  acm_ep_addr         dest;
	struct ib_acm_resolve_data data;
};

//struct acm_cm_param
//{
//	uint32_t qpn;
//	uint8_t  init_depth;
//	uint8_t  resp_resources;
//	uint8_t  retry_cnt;
//	uint8_t  rnr_retry_cnt;
//	uint16_t src_port;
//	uint16_t dest_port;
//	uint8_t  reserved[4];
//};

//struct acm_cm_msg
//{
//	struct acm_hdr      hdr;
//	union  acm_ep_addr  src;
//	union  acm_ep_addr  dest;
//	struct acm_cm_param param;
//};

#define ACM_QUERY_PATH_RECORD  0x01
#define ACM_QUERY_SA           0x80

#define ACM_EP_TYPE_LID        0x01
#define ACM_EP_TYPE_GID        0x02

union acm_query_data
{
	struct ib_path_record  path;
};

struct acm_query_msg
{
	struct acm_hdr         hdr;
	union acm_query_data   data;
	uint8_t                reserved[16];
};

#define ACM_MSG_DATA_SIZE  80

struct acm_msg
{
	struct acm_hdr     hdr;
	uint8_t            data[ACM_MSG_DATA_SIZE];
};

#endif /* ACM_H */
