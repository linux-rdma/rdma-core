/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
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

#ifndef _HNS_ROCE_U_HW_V2_H
#define _HNS_ROCE_U_HW_V2_H

enum {
	CQE_FOR_SQ,
	CQE_FOR_RQ,
};

#define HNS_ROCE_V2_CQ_DB_REQ_SOL		1
#define HNS_ROCE_V2_CQ_DB_REQ_NEXT		0

#define HNS_ROCE_CMDSN_MASK			0x3

/* V2 REG DEFINITION */
#define ROCEE_VF_DB_CFG0_OFFSET			0x0230

#define HNS_ROCE_IDX_QUE_ENTRY_SZ		4

enum {
	HNS_ROCE_WQE_OP_SEND = 0x0,
	HNS_ROCE_WQE_OP_SEND_WITH_INV = 0x1,
	HNS_ROCE_WQE_OP_SEND_WITH_IMM = 0x2,
	HNS_ROCE_WQE_OP_RDMA_WRITE = 0x3,
	HNS_ROCE_WQE_OP_RDMA_WRITE_WITH_IMM = 0x4,
	HNS_ROCE_WQE_OP_RDMA_READ = 0x5,
	HNS_ROCE_WQE_OP_ATOMIC_COM_AND_SWAP = 0x6,
	HNS_ROCE_WQE_OP_ATOMIC_FETCH_AND_ADD = 0x7,
	HNS_ROCE_WQE_OP_ATOMIC_MASK_COMP_AND_SWAP = 0x8,
	HNS_ROCE_WQE_OP_ATOMIC_MASK_FETCH_AND_ADD = 0x9,
	HNS_ROCE_WQE_OP_FAST_REG_PMR = 0xa,
	HNS_ROCE_WQE_OP_LOCAL_INV = 0xb,
	HNS_ROCE_WQE_OP_BIND_MW_TYPE = 0xc,
	HNS_ROCE_WQE_OP_MASK = 0x1f
};

enum {
	/* rq operations */
	HNS_ROCE_RECV_OP_RDMA_WRITE_IMM = 0x0,
	HNS_ROCE_RECV_OP_SEND = 0x1,
	HNS_ROCE_RECV_OP_SEND_WITH_IMM = 0x2,
	HNS_ROCE_RECV_OP_SEND_WITH_INV = 0x3,
};

enum {
	HNS_ROCE_SQ_OP_SEND = 0x0,
	HNS_ROCE_SQ_OP_SEND_WITH_INV = 0x1,
	HNS_ROCE_SQ_OP_SEND_WITH_IMM = 0x2,
	HNS_ROCE_SQ_OP_RDMA_WRITE = 0x3,
	HNS_ROCE_SQ_OP_RDMA_WRITE_WITH_IMM = 0x4,
	HNS_ROCE_SQ_OP_RDMA_READ = 0x5,
	HNS_ROCE_SQ_OP_ATOMIC_COMP_AND_SWAP = 0x6,
	HNS_ROCE_SQ_OP_ATOMIC_FETCH_AND_ADD = 0x7,
	HNS_ROCE_SQ_OP_ATOMIC_MASK_COMP_AND_SWAP = 0x8,
	HNS_ROCE_SQ_OP_ATOMIC_MASK_FETCH_AND_ADD = 0x9,
	HNS_ROCE_SQ_OP_FAST_REG_PMR = 0xa,
	HNS_ROCE_SQ_OP_LOCAL_INV = 0xb,
	HNS_ROCE_SQ_OP_BIND_MW = 0xc,
};

enum {
	V2_CQ_OK			=  0,
	V2_CQ_EMPTY			= -1,
	V2_CQ_POLL_ERR			= -2,
};

enum {
	HNS_ROCE_V2_CQE_SUCCESS				= 0x00,
	HNS_ROCE_V2_CQE_LOCAL_LENGTH_ERR		= 0x01,
	HNS_ROCE_V2_CQE_LOCAL_QP_OP_ERR			= 0x02,
	HNS_ROCE_V2_CQE_LOCAL_PROT_ERR			= 0x04,
	HNS_ROCE_V2_CQE_WR_FLUSH_ERR			= 0x05,
	HNS_ROCE_V2_CQE_MEM_MANAGERENT_OP_ERR		= 0x06,
	HNS_ROCE_V2_CQE_BAD_RESP_ERR			= 0x10,
	HNS_ROCE_V2_CQE_LOCAL_ACCESS_ERR		= 0x11,
	HNS_ROCE_V2_CQE_REMOTE_INVAL_REQ_ERR		= 0x12,
	HNS_ROCE_V2_CQE_REMOTE_ACCESS_ERR		= 0x13,
	HNS_ROCE_V2_CQE_REMOTE_OP_ERR			= 0x14,
	HNS_ROCE_V2_CQE_TRANSPORT_RETRY_EXC_ERR		= 0x15,
	HNS_ROCE_V2_CQE_RNR_RETRY_EXC_ERR		= 0x16,
	HNS_ROCE_V2_CQE_REMOTE_ABORTED_ERR		= 0x22,
	HNS_ROCE_V2_CQE_XRC_VIOLATION_ERR		= 0x24,
};

enum {
	HNS_ROCE_V2_SQ_DB,
	HNS_ROCE_V2_RQ_DB,
	HNS_ROCE_V2_SRQ_DB,
	HNS_ROCE_V2_CQ_DB_PTR,
	HNS_ROCE_V2_CQ_DB_NTR,
};

struct hns_roce_db {
	__le32	byte_4;
	__le32	parameter;
};
#define DB_BYTE_4_TAG_S 0
#define DB_BYTE_4_TAG_M GENMASK(23, 0)

#define DB_BYTE_4_CMD_S 24
#define DB_BYTE_4_CMD_M GENMASK(27, 24)

#define DB_PARAM_SRQ_PRODUCER_COUNTER_S 0
#define DB_PARAM_SRQ_PRODUCER_COUNTER_M GENMASK(15, 0)

#define DB_PARAM_SL_S 16
#define DB_PARAM_SL_M GENMASK(18, 16)

#define DB_PARAM_CQ_CONSUMER_IDX_S 0
#define DB_PARAM_CQ_CONSUMER_IDX_M GENMASK(23, 0)

#define DB_PARAM_CQ_NOTIFY_S 24

#define DB_PARAM_CQ_CMD_SN_S 25
#define DB_PARAM_CQ_CMD_SN_M GENMASK(26, 25)

struct hns_roce_v2_cqe {
	__le32	byte_4;
	union {
		__le32	rkey;
		__le32	immtdata;
	};
	__le32	byte_12;
	__le32	byte_16;
	__le32	byte_cnt;
	__le32	smac;
	__le32	byte_28;
	__le32	byte_32;
	__le32	rsv[8];
};

#define CQE_BYTE_4_OPCODE_S 0
#define CQE_BYTE_4_OPCODE_M   (((1UL << 5) - 1) << CQE_BYTE_4_OPCODE_S)

#define CQE_BYTE_4_RQ_INLINE_S 5

#define CQE_BYTE_4_S_R_S 6
#define CQE_BYTE_4_OWNER_S 7

#define CQE_BYTE_4_STATUS_S 8
#define CQE_BYTE_4_STATUS_M   (((1UL << 8) - 1) << CQE_BYTE_4_STATUS_S)

#define CQE_BYTE_4_WQE_IDX_S 16
#define CQE_BYTE_4_WQE_IDX_M   (((1UL << 16) - 1) << CQE_BYTE_4_WQE_IDX_S)

#define CQE_BYTE_12_XRC_SRQN_S 0
#define CQE_BYTE_12_XRC_SRQN_M   (((1UL << 24) - 1) << CQE_BYTE_12_XRC_SRQN_S)

#define CQE_BYTE_16_LCL_QPN_S 0
#define CQE_BYTE_16_LCL_QPN_M   (((1UL << 24) - 1) << CQE_BYTE_16_LCL_QPN_S)

#define CQE_BYTE_28_SMAC_S 0
#define CQE_BYTE_28_SMAC_M   (((1UL << 16) - 1) << CQE_BYTE_28_SMAC_S)

#define CQE_BYTE_28_PORT_TYPE_S 16
#define CQE_BYTE_28_PORT_TYPE_M   (((1UL << 2) - 1) << CQE_BYTE_28_PORT_TYPE_S)

#define CQE_BYTE_32_RMT_QPN_S 0
#define CQE_BYTE_32_RMT_QPN_M   (((1UL << 24) - 1) << CQE_BYTE_32_RMT_QPN_S)

#define CQE_BYTE_32_SL_S 24
#define CQE_BYTE_32_SL_M   (((1UL << 3) - 1) << CQE_BYTE_32_SL_S)

#define CQE_BYTE_32_PORTN_S 27
#define CQE_BYTE_32_PORTN_M   (((1UL << 3) - 1) << CQE_BYTE_32_PORTN_S)

#define CQE_BYTE_32_GRH_S 30

#define CQE_BYTE_32_LPK_S 31

struct hns_roce_rc_sq_wqe {
	__le32	byte_4;
	__le32	msg_len;
	union {
		__le32	inv_key;
		__le32	immtdata;
		__le32	new_rkey;
	};
	__le32	byte_16;
	__le32	byte_20;
	__le32	rkey;
	__le64	va;
};

#define RC_SQ_WQE_BYTE_4_OPCODE_S 0
#define RC_SQ_WQE_BYTE_4_OPCODE_M \
	(((1UL << 5) - 1) << RC_SQ_WQE_BYTE_4_OPCODE_S)

#define RC_SQ_WQE_BYTE_4_OWNER_S 7

#define RC_SQ_WQE_BYTE_4_CQE_S 8

#define RC_SQ_WQE_BYTE_4_FENCE_S 9

#define RC_SQ_WQE_BYTE_4_SO_S 10

#define RC_SQ_WQE_BYTE_4_SE_S 11

#define RC_SQ_WQE_BYTE_4_INLINE_S 12

#define RC_SQ_WQE_BYTE_4_MW_TYPE_S 14

#define RC_SQ_WQE_BYTE_4_ATOMIC_S 20

#define RC_SQ_WQE_BYTE_4_RDMA_READ_S 21

#define RC_SQ_WQE_BYTE_4_RDMA_WRITE_S 22

#define RC_SQ_WQE_BYTE_16_XRC_SRQN_S 0
#define RC_SQ_WQE_BYTE_16_XRC_SRQN_M \
	(((1UL << 24) - 1) << RC_SQ_WQE_BYTE_16_XRC_SRQN_S)

#define RC_SQ_WQE_BYTE_16_SGE_NUM_S 24
#define RC_SQ_WQE_BYTE_16_SGE_NUM_M \
	(((1UL << 8) - 1) << RC_SQ_WQE_BYTE_16_SGE_NUM_S)

#define RC_SQ_WQE_BYTE_20_MSG_START_SGE_IDX_S 0
#define RC_SQ_WQE_BYTE_20_MSG_START_SGE_IDX_M \
	(((1UL << 24) - 1) << RC_SQ_WQE_BYTE_20_MSG_START_SGE_IDX_S)

#define RC_SQ_WQE_BYTE_20_INL_TYPE_S 31

struct hns_roce_v2_wqe_data_seg {
	__le32		len;
	__le32		lkey;
	__le64		addr;
};

struct hns_roce_v2_wqe_raddr_seg {
	__le32		rkey;
	__le32		len;
	__le64		raddr;
};

struct hns_roce_wqe_atomic_seg {
	__le64		fetchadd_swap_data;
	__le64		cmp_data;
};

int hns_roce_u_v2_post_send(struct ibv_qp *ibvqp, struct ibv_send_wr *wr,
			    struct ibv_send_wr **bad_wr);

static inline unsigned int is_std_atomic(unsigned int len)
{
	return len == 8;
}

static inline unsigned int is_ext_atomic(unsigned int len)
{
	return len == 16 || len == 32 || len == 64;
}

static inline unsigned int is_atomic(unsigned int len)
{
	return is_std_atomic(len) || is_ext_atomic(len);
}

#define ATOMIC_DATA_LEN_MAX 64
#define ATOMIC_BUF_NUM_MAX 2

struct hns_roce_ud_sq_wqe {
	__le32 rsv_opcode;
	__le32 msg_len;
	__le32 immtdata;
	__le32 sge_num_pd;
	__le32 rsv_msg_start_sge_idx;
	__le32 udpspn_rsv;
	__le32 qkey;
	__le32 rsv_dqpn;
	__le32 tclass_vlan;
	__le32 lbi_flow_label;
	uint8_t dmac[ETH_ALEN];
	uint8_t sgid_index;
	uint8_t smac_index;
	uint8_t dgid[HNS_ROCE_GID_SIZE];
};

#define UD_SQ_WQE_OPCODE_S 0
#define UD_SQ_WQE_OPCODE_M GENMASK(4, 0)

#define UD_SQ_WQE_DB_SL_L_S 5
#define UD_SQ_WQE_DB_SL_L_M GENMASK(6, 5)

#define UD_SQ_WQE_DB_SL_H_S 13
#define UD_SQ_WQE_DB_SL_H_M GENMASK(14, 13)

#define UD_SQ_WQE_INDEX_S 15
#define UD_SQ_WQE_INDEX_M GENMASK(30, 15)

#define UD_SQ_WQE_OWNER_S 7

#define UD_SQ_WQE_CQE_S 8

#define UD_SQ_WQE_SE_S 11

#define UD_SQ_WQE_FLAG_S 31

#define UD_SQ_WQE_PD_S 0
#define UD_SQ_WQE_PD_M GENMASK(23, 0)

#define UD_SQ_WQE_SGE_NUM_S 24
#define UD_SQ_WQE_SGE_NUM_M GENMASK(31, 24)

#define UD_SQ_WQE_MSG_START_SGE_IDX_S 0
#define UD_SQ_WQE_MSG_START_SGE_IDX_M GENMASK(23, 0)

#define UD_SQ_WQE_UDP_SPN_S 16
#define UD_SQ_WQE_UDP_SPN_M GENMASK(31, 16)

#define UD_SQ_WQE_DQPN_S 0
#define UD_SQ_WQE_DQPN_M GENMASK(23, 0)

#define UD_SQ_WQE_VLAN_S 0
#define UD_SQ_WQE_VLAN_M GENMASK(15, 0)

#define UD_SQ_WQE_HOPLIMIT_S 16
#define UD_SQ_WQE_HOPLIMIT_M GENMASK(23, 16)

#define UD_SQ_WQE_TCLASS_S 24
#define UD_SQ_WQE_TCLASS_M GENMASK(31, 24)

#define UD_SQ_WQE_FLOW_LABEL_S 0
#define UD_SQ_WQE_FLOW_LABEL_M GENMASK(19, 0)

#define UD_SQ_WQE_SL_S 20
#define UD_SQ_WQE_SL_M GENMASK(23, 20)

#define UD_SQ_WQE_VLAN_EN_S 30

#define UD_SQ_WQE_LBI_S 31

#define UD_SQ_WQE_BYTE_4_INL_S 12
#define UD_SQ_WQE_BYTE_20_INL_TYPE_S 31

#define UD_SQ_WQE_BYTE_8_INL_DATE_15_0_S 16
#define UD_SQ_WQE_BYTE_8_INL_DATE_15_0_M GENMASK(31, 16)
#define UD_SQ_WQE_BYTE_16_INL_DATA_23_16_S 24
#define UD_SQ_WQE_BYTE_16_INL_DATA_23_16_M GENMASK(31, 24)
#define UD_SQ_WQE_BYTE_20_INL_DATA_47_24_S 0
#define UD_SQ_WQE_BYTE_20_INL_DATA_47_24_M GENMASK(23, 0)
#define UD_SQ_WQE_BYTE_24_INL_DATA_63_48_S 0
#define UD_SQ_WQE_BYTE_24_INL_DATA_63_48_M GENMASK(15, 0)

#define MAX_SERVICE_LEVEL 0x7

#endif /* _HNS_ROCE_U_HW_V2_H */
