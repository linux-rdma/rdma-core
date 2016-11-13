/*
 * Copyright (c) 2016 Hisilicon Limited.
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

#ifndef _HNS_ROCE_U_HW_V1_H
#define _HNS_ROCE_U_HW_V1_H

#define HNS_ROCE_CQ_DB_REQ_SOL			1
#define HNS_ROCE_CQ_DB_REQ_NEXT			0

#define HNS_ROCE_CQE_IS_SQ			0

#define HNS_ROCE_RC_WQE_INLINE_DATA_MAX_LEN	32

enum {
	HNS_ROCE_WQE_IMM		= 1 << 23,
	HNS_ROCE_WQE_OPCODE_SEND        = 0 << 16,
	HNS_ROCE_WQE_OPCODE_RDMA_READ   = 1 << 16,
	HNS_ROCE_WQE_OPCODE_RDMA_WRITE  = 2 << 16,
	HNS_ROCE_WQE_OPCODE_BIND_MW2    = 6 << 16,
	HNS_ROCE_WQE_OPCODE_MASK        = 15 << 16,
};

struct hns_roce_wqe_ctrl_seg {
	__be32		sgl_pa_h;
	__be32		flag;
};

enum {
	CQ_OK				=  0,
	CQ_EMPTY			= -1,
	CQ_POLL_ERR			= -2,
};

enum {
	HNS_ROCE_CQE_QPN_MASK		= 0x3ffff,
	HNS_ROCE_CQE_STATUS_MASK	= 0x1f,
	HNS_ROCE_CQE_OPCODE_MASK	= 0xf,
};

enum {
	HNS_ROCE_CQE_SUCCESS,
	HNS_ROCE_CQE_SYNDROME_LOCAL_LENGTH_ERR,
	HNS_ROCE_CQE_SYNDROME_LOCAL_QP_OP_ERR,
	HNS_ROCE_CQE_SYNDROME_LOCAL_PROT_ERR,
	HNS_ROCE_CQE_SYNDROME_WR_FLUSH_ERR,
	HNS_ROCE_CQE_SYNDROME_MEM_MANAGE_OPERATE_ERR,
	HNS_ROCE_CQE_SYNDROME_BAD_RESP_ERR,
	HNS_ROCE_CQE_SYNDROME_LOCAL_ACCESS_ERR,
	HNS_ROCE_CQE_SYNDROME_REMOTE_INVAL_REQ_ERR,
	HNS_ROCE_CQE_SYNDROME_REMOTE_ACCESS_ERR,
	HNS_ROCE_CQE_SYNDROME_REMOTE_OP_ERR,
	HNS_ROCE_CQE_SYNDROME_TRANSPORT_RETRY_EXC_ERR,
	HNS_ROCE_CQE_SYNDROME_RNR_RETRY_EXC_ERR,
};

struct hns_roce_cq_db {
	unsigned int u32_4;
	unsigned int u32_8;
};
#define CQ_DB_U32_4_CONS_IDX_S 0
#define CQ_DB_U32_4_CONS_IDX_M   (((1UL << 16) - 1) << CQ_DB_U32_4_CONS_IDX_S)

#define CQ_DB_U32_8_CQN_S 0
#define CQ_DB_U32_8_CQN_M   (((1UL << 16) - 1) << CQ_DB_U32_8_CQN_S)

#define CQ_DB_U32_8_NOTIFY_TYPE_S 16

#define CQ_DB_U32_8_CMD_MDF_S 24
#define CQ_DB_U32_8_CMD_MDF_M   (((1UL << 4) - 1) << CQ_DB_U32_8_CMD_MDF_S)

#define CQ_DB_U32_8_CMD_S 28
#define CQ_DB_U32_8_CMD_M   (((1UL << 3) - 1) << CQ_DB_U32_8_CMD_S)

#define CQ_DB_U32_8_HW_SYNC_S 31

struct hns_roce_cqe {
	unsigned int cqe_byte_4;
	union {
		unsigned int r_key;
		unsigned int immediate_data;
	};
	unsigned int byte_cnt;
	unsigned int cqe_byte_16;
	unsigned int cqe_byte_20;
	unsigned int s_mac_l;
	unsigned int cqe_byte_28;
	unsigned int reserved;
};
#define CQE_BYTE_4_OPERATION_TYPE_S 0
#define CQE_BYTE_4_OPERATION_TYPE_M   \
	(((1UL << 4) - 1) << CQE_BYTE_4_OPERATION_TYPE_S)

#define CQE_BYTE_4_OWNER_S 7

#define CQE_BYTE_4_STATUS_OF_THE_OPERATION_S 8
#define CQE_BYTE_4_STATUS_OF_THE_OPERATION_M   \
	(((1UL << 5) - 1) << CQE_BYTE_4_STATUS_OF_THE_OPERATION_S)

#define CQE_BYTE_4_SQ_RQ_FLAG_S 14

#define CQE_BYTE_4_IMMEDIATE_DATA_FLAG_S 15

#define CQE_BYTE_4_WQE_INDEX_S 16
#define CQE_BYTE_4_WQE_INDEX_M	(((1UL << 14) - 1) << CQE_BYTE_4_WQE_INDEX_S)

#define CQE_BYTE_16_LOCAL_QPN_S 0
#define CQE_BYTE_16_LOCAL_QPN_M	(((1UL << 24) - 1) << CQE_BYTE_16_LOCAL_QPN_S)

#define ROCEE_DB_SQ_L_0_REG				0x230

#define ROCEE_DB_OTHERS_L_0_REG				0x238

struct hns_roce_rc_send_wqe {
	unsigned int sgl_ba_31_0;
	unsigned int u32_1;
	union {
		unsigned int r_key;
		unsigned int immediate_data;
	};
	unsigned int msg_length;
	unsigned int rvd_3;
	unsigned int rvd_4;
	unsigned int rvd_5;
	unsigned int rvd_6;
	uint64_t     va0;
	unsigned int l_key0;
	unsigned int length0;

	uint64_t     va1;
	unsigned int l_key1;
	unsigned int length1;
};

#endif /* _HNS_ROCE_U_HW_V1_H */
