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

#define ACM_VERSION             1

#define ACM_OP_MASK             0x0F
#define ACM_OP_RESOLVE          0x01
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

#define ACM_MSG_HDR_LENGTH      16
#define ACM_MAX_ADDRESS         64
#define ACM_MSG_EP_LENGTH       72
/*
 * Support up to 6 path records (primary and alternate CM paths,
 * inbound and outbound primary and alternate data paths), plus CM data.
 */
#define ACM_MSG_DATA_LENGTH     (ACM_MSG_EP_LENGTH * 8)

struct acm_hdr
{
	uint8_t                 version;
	uint8_t                 opcode;
	uint8_t                 status;
	uint8_t		        reserved[3];
	uint16_t                length;
	uint64_t                tid;
};

#define ACM_EP_INFO_NAME        0x0001
#define ACM_EP_INFO_ADDRESS_IP  0x0002
#define ACM_EP_INFO_ADDRESS_IP6 0x0003
#define ACM_EP_INFO_PATH        0x0010

union acm_ep_info
{
	uint8_t                 addr[ACM_MAX_ADDRESS];
	uint8_t                 name[ACM_MAX_ADDRESS];
	struct ib_path_record   path;
};

#define ACM_EP_FLAG_SOURCE      (1<<0)
#define ACM_EP_FLAG_DEST        (1<<1)

struct acm_ep_addr_data
{
	uint32_t                flags;
	uint16_t                type;
	uint16_t                reserved;
	union acm_ep_info       info;
};

struct acm_resolve_msg
{
	struct acm_hdr          hdr;
	struct acm_ep_addr_data data[0];
};

struct acm_msg
{
	struct acm_hdr          hdr;
	uint8_t                 data[ACM_MSG_DATA_LENGTH];
};

#endif /* ACM_H */
