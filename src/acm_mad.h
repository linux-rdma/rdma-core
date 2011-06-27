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

#if !defined(ACM_MAD_H)
#define ACM_MAD_H

#include <infiniband/verbs.h>
#include <infiniband/acm.h>
#include <netinet/in.h>

#define ACM_SEND_SIZE 256
#define ACM_RECV_SIZE (ACM_SEND_SIZE + sizeof(struct ibv_grh))

#define IB_METHOD_GET       0x01
#define IB_METHOD_SET       0x02
#define IB_METHOD_SEND      0x03
#define IB_METHOD_GET_TABLE 0x12
#define IB_METHOD_DELETE    0x15
#define IB_METHOD_RESP      0x80

#define ACM_MGMT_CLASS   0x2C

#define ACM_CTRL_ACK     htons(0x8000)
#define ACM_CTRL_RESOLVE htons(0x0001)

struct acm_mad {
	uint8_t  base_version;
	uint8_t  mgmt_class;
	uint8_t  class_version;
	uint8_t  method;
	uint16_t status;
	uint16_t control;
	uint64_t tid;

	uint8_t  data[240];
};

#define acm_class_status(status) ((uint8_t) (ntohs(status) >> 8))

#define ACM_QKEY 0x80010000

/* Map to ACM_EP_INFO_* */
#define ACM_ADDRESS_INVALID    0x00
#define ACM_ADDRESS_NAME       0x01
#define ACM_ADDRESS_IP         0x02
#define ACM_ADDRESS_IP6        0x03
#define ACM_ADDRESS_GID        0x04
#define ACM_ADDRESS_LID        0x05
#define ACM_ADDRESS_RESERVED   0x06  /* start of reserved range */

#define ACM_MAX_GID_COUNT        10

struct acm_resolve_rec {
	uint8_t       dest_type;
	uint8_t       dest_length;
	uint8_t       src_type;
	uint8_t       src_length;
	uint8_t       gid_cnt;
	uint8_t       resp_resources;
	uint8_t       init_depth;
	uint8_t       reserved;
	uint8_t       dest[ACM_MAX_ADDRESS];
	uint8_t       src[ACM_MAX_ADDRESS];
	union ibv_gid gid[ACM_MAX_GID_COUNT];
};

#define IB_MGMT_CLASS_SA 0x03

struct ib_sa_mad {
	uint8_t  base_version;
	uint8_t  mgmt_class;
	uint8_t  class_version;
	uint8_t  method;
	uint16_t status;
	uint16_t reserved1;
	uint64_t tid;
	uint16_t attr_id;
	uint16_t reserved2;
	uint32_t attr_mod;

	uint8_t  rmpp_version;
	uint8_t  rmpp_type;
	uint8_t  rmpp_flags;
	uint8_t  rmpp_status;
	uint32_t seg_num;
	uint32_t paylen_newwin;

	uint32_t sm_key[2];
	uint16_t attr_offset;
	uint16_t reserved3;
	uint64_t comp_mask;

	uint8_t  data[200];
};

#define IB_SA_ATTR_PATH_REC htons(0x0035)

#define IB_COMP_MASK_PR_SERVICE_ID         (htonll(1 << 0) | \
                                            htonll(1 << 1))
#define IB_COMP_MASK_PR_DGID                htonll(1 << 2)
#define IB_COMP_MASK_PR_SGID                htonll(1 << 3)
#define IB_COMP_MASK_PR_DLID                htonll(1 << 4)
#define IB_COMP_MASK_PR_SLID                htonll(1 << 5)
#define IB_COMP_MASK_PR_RAW_TRAFFIC         htonll(1 << 6)
/* RESERVED                                 htonll(1 << 7) */
#define IB_COMP_MASK_PR_FLOW_LABEL          htonll(1 << 8)
#define IB_COMP_MASK_PR_HOP_LIMIT           htonll(1 << 9)
#define IB_COMP_MASK_PR_TCLASS              htonll(1 << 10)
#define IB_COMP_MASK_PR_REVERSIBLE          htonll(1 << 11)
#define IB_COMP_MASK_PR_NUM_PATH            htonll(1 << 12)
#define IB_COMP_MASK_PR_PKEY                htonll(1 << 13)
#define IB_COMP_MASK_PR_QOS_CLASS           htonll(1 << 14)
#define IB_COMP_MASK_PR_SL                  htonll(1 << 15)
#define IB_COMP_MASK_PR_MTU_SELECTOR        htonll(1 << 16)
#define IB_COMP_MASK_PR_MTU                 htonll(1 << 17)
#define IB_COMP_MASK_PR_RATE_SELECTOR       htonll(1 << 18)
#define IB_COMP_MASK_PR_RATE                htonll(1 << 19)
#define IB_COMP_MASK_PR_PACKET_LIFETIME_SELECTOR htonll(1 << 20)
#define IB_COMP_MASK_PR_PACKET_LIFETIME     htonll(1 << 21)
#define IB_COMP_MASK_PR_PREFERENCE          htonll(1 << 22)
/* RESERVED                                 htonll(1 << 23) */

#define IB_MC_QPN 0xffffff
#define IB_SA_ATTR_MC_MEMBER_REC htons(0x0038)

#define IB_COMP_MASK_MC_MGID                htonll(1 << 0)
#define IB_COMP_MASK_MC_PORT_GID            htonll(1 << 1)
#define IB_COMP_MASK_MC_QKEY                htonll(1 << 2)
#define IB_COMP_MASK_MC_MLID                htonll(1 << 3)
#define IB_COMP_MASK_MC_MTU_SEL             htonll(1 << 4)
#define IB_COMP_MASK_MC_MTU                 htonll(1 << 5)
#define IB_COMP_MASK_MC_TCLASS              htonll(1 << 6)
#define IB_COMP_MASK_MC_PKEY                htonll(1 << 7)
#define IB_COMP_MASK_MC_RATE_SEL            htonll(1 << 8)
#define IB_COMP_MASK_MC_RATE                htonll(1 << 9)
#define IB_COMP_MASK_MC_PACKET_LIFETIME_SEL htonll(1 << 10)
#define IB_COMP_MASK_MC_PACKET_LIFETIME     htonll(1 << 11)
#define IB_COMP_MASK_MC_SL                  htonll(1 << 12)
#define IB_COMP_MASK_MC_FLOW                htonll(1 << 13)
#define IB_COMP_MASK_MC_HOP                 htonll(1 << 14)
#define IB_COMP_MASK_MC_SCOPE               htonll(1 << 15)
#define IB_COMP_MASK_MC_JOIN_STATE          htonll(1 << 16)
#define IB_COMP_MASK_MC_PROXY_JOIN          htonll(1 << 17)

struct ib_mc_member_rec {
	union ibv_gid mgid;
	union ibv_gid port_gid;
	uint32_t      qkey;
	uint16_t      mlid;
	uint8_t       mtu;
	uint8_t       tclass;
	uint16_t      pkey;
	uint8_t       rate;
	uint8_t       packet_lifetime;
	uint32_t      sl_flow_hop;
	uint8_t       scope_state;
	uint8_t       proxy_join;
	uint8_t       reserved[2];
	uint8_t       pad[4];
};

#endif /* ACM_MAD_H */
