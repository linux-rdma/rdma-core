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

#define HNS_ROCE_SL_SHIFT 2

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
	HNS_ROCE_V2_CQE_GENERAL_ERR			= 0x23,
	HNS_ROCE_V2_CQE_XRC_VIOLATION_ERR		= 0x24,
};

enum {
	HNS_ROCE_V2_SQ_DB,
	HNS_ROCE_V2_RQ_DB,
	HNS_ROCE_V2_SRQ_DB,
	HNS_ROCE_V2_CQ_DB_PTR,
	HNS_ROCE_V2_CQ_DB_NTR,
};

enum hns_roce_wr_buf_type {
	WR_BUF_TYPE_POST_SEND,
	WR_BUF_TYPE_SEND_WR_OPS,
};

struct hns_roce_db {
	__le32	byte_4;
	__le32	parameter;
};

#define DB_FIELD_LOC(h, l) FIELD_LOC(struct hns_roce_db, h, l)

#define DB_TAG DB_FIELD_LOC(23, 0)
#define DB_CMD DB_FIELD_LOC(27, 24)
#define DB_FLAG DB_FIELD_LOC(31, 31)
#define DB_PI DB_FIELD_LOC(47, 32)
#define DB_SL DB_FIELD_LOC(50, 48)
#define DB_CQ_CI DB_FIELD_LOC(55, 32)
#define DB_CQ_NOTIFY DB_FIELD_LOC(56, 56)
#define DB_CQ_CMD_SN DB_FIELD_LOC(58, 57)

#define RECORD_DB_CI_MASK GENMASK(23, 0)

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
	__le32	payload[8];
};

#define CQE_FIELD_LOC(h, l) FIELD_LOC(struct hns_roce_v2_cqe, h, l)

#define CQE_OPCODE CQE_FIELD_LOC(4, 0)
#define CQE_RQ_INLINE CQE_FIELD_LOC(5, 5)
#define CQE_S_R CQE_FIELD_LOC(6, 6)
#define CQE_OWNER CQE_FIELD_LOC(7, 7)
#define CQE_STATUS CQE_FIELD_LOC(15, 8)
#define CQE_WQE_IDX CQE_FIELD_LOC(31, 16)
#define CQE_RKEY_IMMTDATA CQE_FIELD_LOC(63, 32)
#define CQE_XRC_SRQN CQE_FIELD_LOC(87, 64)
#define CQE_CQE_INLINE CQE_FIELD_LOC(89, 88)
#define CQE_LCL_QPN CQE_FIELD_LOC(119, 96)
#define CQE_SUB_STATUS CQE_FIELD_LOC(127, 120)
#define CQE_BYTE_CNT CQE_FIELD_LOC(159, 128)
#define CQE_SMAC CQE_FIELD_LOC(207, 160)
#define CQE_PORT_TYPE CQE_FIELD_LOC(209, 208)
#define CQE_VID CQE_FIELD_LOC(221, 210)
#define CQE_VID_VLD CQE_FIELD_LOC(222, 222)
#define CQE_RSV2 CQE_FIELD_LOC(223, 223)
#define CQE_RMT_QPN CQE_FIELD_LOC(247, 224)
#define CQE_SL CQE_FIELD_LOC(250, 248)
#define CQE_PORTN CQE_FIELD_LOC(253, 251)
#define CQE_GRH CQE_FIELD_LOC(254, 254)
#define CQE_LPK CQE_FIELD_LOC(255, 255)
#define CQE_RSV3 CQE_FIELD_LOC(511, 256)

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

#define RCWQE_FIELD_LOC(h, l) FIELD_LOC(struct hns_roce_rc_sq_wqe, h, l)

#define RCWQE_OPCODE RCWQE_FIELD_LOC(4, 0)
#define RCWQE_DB_SL_L RCWQE_FIELD_LOC(6, 5)
#define RCWQE_SQPN_L RCWQE_FIELD_LOC(6, 5)
#define RCWQE_OWNER RCWQE_FIELD_LOC(7, 7)
#define RCWQE_CQE RCWQE_FIELD_LOC(8, 8)
#define RCWQE_FENCE RCWQE_FIELD_LOC(9, 9)
#define RCWQE_SO RCWQE_FIELD_LOC(10, 10)
#define RCWQE_SE RCWQE_FIELD_LOC(11, 11)
#define RCWQE_INLINE RCWQE_FIELD_LOC(12, 12)
#define RCWQE_DB_SL_H RCWQE_FIELD_LOC(14, 13)
#define RCWQE_WQE_IDX RCWQE_FIELD_LOC(30, 15)
#define RCWQE_SQPN_H RCWQE_FIELD_LOC(30, 13)
#define RCWQE_FLAG RCWQE_FIELD_LOC(31, 31)
#define RCWQE_MSG_LEN RCWQE_FIELD_LOC(63, 32)
#define RCWQE_INV_KEY_IMMTDATA RCWQE_FIELD_LOC(95, 64)
#define RCWQE_XRC_SRQN RCWQE_FIELD_LOC(119, 96)
#define RCWQE_SGE_NUM RCWQE_FIELD_LOC(127, 120)
#define RCWQE_MSG_START_SGE_IDX RCWQE_FIELD_LOC(151, 128)
#define RCWQE_REDUCE_CODE RCWQE_FIELD_LOC(158, 152)
#define RCWQE_INLINE_TYPE RCWQE_FIELD_LOC(159, 159)
#define RCWQE_RKEY RCWQE_FIELD_LOC(191, 160)
#define RCWQE_VA_L RCWQE_FIELD_LOC(223, 192)
#define RCWQE_VA_H RCWQE_FIELD_LOC(255, 224)
#define RCWQE_LEN0 RCWQE_FIELD_LOC(287, 256)
#define RCWQE_LKEY0 RCWQE_FIELD_LOC(319, 288)
#define RCWQE_VA0_L RCWQE_FIELD_LOC(351, 320)
#define RCWQE_VA0_H RCWQE_FIELD_LOC(383, 352)
#define RCWQE_LEN1 RCWQE_FIELD_LOC(415, 384)
#define RCWQE_LKEY1 RCWQE_FIELD_LOC(447, 416)
#define RCWQE_VA1_L RCWQE_FIELD_LOC(479, 448)
#define RCWQE_VA1_H RCWQE_FIELD_LOC(511, 480)

#define RCWQE_MW_TYPE RCWQE_FIELD_LOC(256, 256)
#define RCWQE_MW_RA_EN RCWQE_FIELD_LOC(258, 258)
#define RCWQE_MW_RR_EN RCWQE_FIELD_LOC(259, 259)
#define RCWQE_MW_RW_EN RCWQE_FIELD_LOC(260, 260)

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

#define UDWQE_FIELD_LOC(h, l) FIELD_LOC(struct hns_roce_ud_sq_wqe, h, l)

#define UDWQE_OPCODE UDWQE_FIELD_LOC(4, 0)
#define UDWQE_DB_SL_L UDWQE_FIELD_LOC(6, 5)
#define UDWQE_OWNER UDWQE_FIELD_LOC(7, 7)
#define UDWQE_CQE UDWQE_FIELD_LOC(8, 8)
#define UDWQE_RSVD1 UDWQE_FIELD_LOC(10, 9)
#define UDWQE_SE UDWQE_FIELD_LOC(11, 11)
#define UDWQE_INLINE UDWQE_FIELD_LOC(12, 12)
#define UDWQE_DB_SL_H UDWQE_FIELD_LOC(14, 13)
#define UDWQE_WQE_IDX UDWQE_FIELD_LOC(30, 15)
#define UDWQE_FLAG UDWQE_FIELD_LOC(31, 31)
#define UDWQE_MSG_LEN UDWQE_FIELD_LOC(63, 32)
#define UDWQE_IMMTDATA UDWQE_FIELD_LOC(95, 64)
#define UDWQE_PD UDWQE_FIELD_LOC(119, 96)
#define UDWQE_SGE_NUM UDWQE_FIELD_LOC(127, 120)
#define UDWQE_MSG_START_SGE_IDX UDWQE_FIELD_LOC(151, 128)
#define UDWQE_RSVD3 UDWQE_FIELD_LOC(158, 152)
#define UDWQE_INLINE_TYPE UDWQE_FIELD_LOC(159, 159)
#define UDWQE_RSVD4 UDWQE_FIELD_LOC(175, 160)
#define UDWQE_UDPSPN UDWQE_FIELD_LOC(191, 176)
#define UDWQE_QKEY UDWQE_FIELD_LOC(223, 192)
#define UDWQE_DQPN UDWQE_FIELD_LOC(247, 224)
#define UDWQE_RSVD5 UDWQE_FIELD_LOC(255, 248)
#define UDWQE_VLAN UDWQE_FIELD_LOC(271, 256)
#define UDWQE_HOPLIMIT UDWQE_FIELD_LOC(279, 272)
#define UDWQE_TCLASS UDWQE_FIELD_LOC(287, 280)
#define UDWQE_FLOW_LABEL UDWQE_FIELD_LOC(307, 288)
#define UDWQE_SL UDWQE_FIELD_LOC(311, 308)
#define UDWQE_PORTN UDWQE_FIELD_LOC(314, 312)
#define UDWQE_RSVD6 UDWQE_FIELD_LOC(317, 315)
#define UDWQE_UD_VLAN_EN UDWQE_FIELD_LOC(318, 318)
#define UDWQE_LBI UDWQE_FIELD_LOC(319, 319)
#define UDWQE_DMAC_L UDWQE_FIELD_LOC(351, 320)
#define UDWQE_DMAC_H UDWQE_FIELD_LOC(367, 352)
#define UDWQE_GMV_IDX UDWQE_FIELD_LOC(383, 368)
#define UDWQE_DGID0 UDWQE_FIELD_LOC(415, 384)
#define UDWQE_DGID1 UDWQE_FIELD_LOC(447, 416)
#define UDWQE_DGID2 UDWQE_FIELD_LOC(479, 448)
#define UDWQE_DGID3 UDWQE_FIELD_LOC(511, 480)

#define UDWQE_INLINE_DATA_15_0 UDWQE_FIELD_LOC(63, 48)
#define UDWQE_INLINE_DATA_23_16 UDWQE_FIELD_LOC(127, 120)
#define UDWQE_INLINE_DATA_47_24 UDWQE_FIELD_LOC(151, 128)
#define UDWQE_INLINE_DATA_63_48 UDWQE_FIELD_LOC(175, 160)

#define MAX_SERVICE_LEVEL 0x7

void hns_roce_v2_clear_qp(struct hns_roce_context *ctx, struct hns_roce_qp *qp);
void hns_roce_attach_cq_ex_ops(struct ibv_cq_ex *cq_ex, uint64_t wc_flags);
int hns_roce_attach_qp_ex_ops(struct ibv_qp_init_attr_ex *attr,
			      struct hns_roce_qp *qp);

#endif /* _HNS_ROCE_U_HW_V2_H */
