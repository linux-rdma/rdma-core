/* SPDX-License-Identifier: GPL-2.0 or OpenIB.org BSD (MIT) See COPYING file */
/*
 * Authors: Cheng Xu <chengyou@linux.alibaba.com>
 * Copyright (c) 2020-2021, Alibaba Group.
 */

#ifndef __ERDMA_HW_H__
#define __ERDMA_HW_H__

#include <stdint.h>

#define ERDMA_SDB_PAGE 0
#define ERDMA_SDB_ENTRY 1
#define ERDMA_SDB_SHARED 2

#define ERDMA_NSDB_PER_ENTRY 2
#define ERDMA_SDB_ALLOC_QPN_MASK 0x1f
#define ERDMA_RDB_ALLOC_QPN_MASK 0x7f

#define ERDMA_SQDB_SIZE 128
#define ERDMA_CQDB_SIZE 8
#define ERDMA_RQDB_SIZE 8
#define ERDMA_RQDB_SPACE_SIZE 32

/* WQE related. */
#define EQE_SIZE 16
#define EQE_SHIFT 4
#define RQE_SIZE 32
#define RQE_SHIFT 5
#define CQE_SIZE 32
#define CQE_SHIFT 5
#define SQEBB_SIZE 32
#define SQEBB_SHIFT 5
#define SQEBB_MASK (~(SQEBB_SIZE - 1))
#define SQEBB_ALIGN(size) ((size + SQEBB_SIZE - 1) & SQEBB_MASK)
#define SQEBB_COUNT(size) (SQEBB_ALIGN(size) >> SQEBB_SHIFT)

#define MAX_WQEBB_PER_SQE 4

enum erdma_opcode {
	ERDMA_OP_WRITE = 0,
	ERDMA_OP_READ = 1,
	ERDMA_OP_SEND = 2,
	ERDMA_OP_SEND_WITH_IMM = 3,

	ERDMA_OP_RECEIVE = 4,
	ERDMA_OP_RECV_IMM = 5,
	ERDMA_OP_RECV_INV = 6,

	ERDMA_OP_REQ_ERR = 7,
	ERDNA_OP_READ_RESPONSE = 8,
	ERDMA_OP_WRITE_WITH_IMM = 9,

	ERDMA_OP_RECV_ERR = 10,

	ERDMA_OP_INVALIDATE = 11,
	ERDMA_OP_RSP_SEND_IMM = 12,
	ERDMA_OP_SEND_WITH_INV = 13,

	ERDMA_OP_REG_MR = 14,
	ERDMA_OP_LOCAL_INV = 15,
	ERDMA_OP_READ_WITH_INV = 16,
	ERDMA_OP_ATOMIC_CAS = 17,
	ERDMA_OP_ATOMIC_FAD = 18,
	ERDMA_NUM_OPCODES = 19,
	ERDMA_OP_INVALID = ERDMA_NUM_OPCODES + 1
};

/*
 * Inline data are kept within the work request itself occupying
 * the space of sge[1] .. sge[n]. Therefore, inline data cannot be
 * supported if ERDMA_MAX_SGE is below 2 elements.
 */
#define ERDMA_MAX_INLINE (sizeof(struct erdma_sge) * (ERDMA_MAX_SEND_SGE))

enum erdma_wc_status {
	ERDMA_WC_SUCCESS = 0,
	ERDMA_WC_GENERAL_ERR = 1,
	ERDMA_WC_RECV_WQE_FORMAT_ERR = 2,
	ERDMA_WC_RECV_STAG_INVALID_ERR = 3,
	ERDMA_WC_RECV_ADDR_VIOLATION_ERR = 4,
	ERDMA_WC_RECV_RIGHT_VIOLATION_ERR = 5,
	ERDMA_WC_RECV_PDID_ERR = 6,
	ERDMA_WC_RECV_WARRPING_ERR = 7,
	ERDMA_WC_SEND_WQE_FORMAT_ERR = 8,
	ERDMA_WC_SEND_WQE_ORD_EXCEED = 9,
	ERDMA_WC_SEND_STAG_INVALID_ERR = 10,
	ERDMA_WC_SEND_ADDR_VIOLATION_ERR = 11,
	ERDMA_WC_SEND_RIGHT_VIOLATION_ERR = 12,
	ERDMA_WC_SEND_PDID_ERR = 13,
	ERDMA_WC_SEND_WARRPING_ERR = 14,
	ERDMA_WC_FLUSH_ERR = 15,
	ERDMA_WC_RETRY_EXC_ERR = 16,
	ERDMA_NUM_WC_STATUS
};

enum erdma_vendor_err {
	ERDMA_WC_VENDOR_NO_ERR = 0,
	ERDMA_WC_VENDOR_INVALID_RQE = 1,
	ERDMA_WC_VENDOR_RQE_INVALID_STAG = 2,
	ERDMA_WC_VENDOR_RQE_ADDR_VIOLATION = 3,
	ERDMA_WC_VENDOR_RQE_ACCESS_RIGHT_ERR = 4,
	ERDMA_WC_VENDOR_RQE_INVALID_PD = 5,
	ERDMA_WC_VENDOR_RQE_WRAP_ERR = 6,
	ERDMA_WC_VENDOR_INVALID_SQE = 0x20,
	ERDMA_WC_VENDOR_ZERO_ORD = 0x21,
	ERDMA_WC_VENDOR_SQE_INVALID_STAG = 0x30,
	ERDMA_WC_VENDOR_SQE_ADDR_VIOLATION = 0x31,
	ERDMA_WC_VENDOR_SQE_ACCESS_ERR = 0x32,
	ERDMA_WC_VENDOR_SQE_INVALID_PD = 0x33,
	ERDMA_WC_VENDOR_SQE_WARP_ERR = 0x34
};

/* Doorbell related. */
#define ERDMA_CQDB_IDX_MASK GENMASK_ULL(63, 56)
#define ERDMA_CQDB_CQN_MASK GENMASK_ULL(55, 32)
#define ERDMA_CQDB_ARM_MASK BIT_ULL(31)
#define ERDMA_CQDB_SOL_MASK BIT_ULL(30)
#define ERDMA_CQDB_CMDSN_MASK GENMASK_ULL(29, 28)
#define ERDMA_CQDB_CI_MASK GENMASK_ULL(23, 0)

#define ERDMA_CQE_QTYPE_SQ 0
#define ERDMA_CQE_QTYPE_RQ 1
#define ERDMA_CQE_QTYPE_CMDQ 2

/* CQE hdr */
#define ERDMA_CQE_HDR_OWNER_MASK BIT(31)
#define ERDMA_CQE_HDR_OPCODE_MASK GENMASK(23, 16)
#define ERDMA_CQE_HDR_QTYPE_MASK GENMASK(15, 8)
#define ERDMA_CQE_HDR_SYNDROME_MASK GENMASK(7, 0)

struct erdma_cqe {
	__be32 hdr;
	__be32 qe_idx;
	__be32 qpn;
	__le32 imm_data;
	__be32 size;
	__be32 rsvd[3];
};

struct erdma_sge {
	__aligned_le64 addr;
	__le32 length;
	__le32 key;
};

/* Receive Queue Element */
struct erdma_rqe {
	__le16 qe_idx;
	__le16 rsvd;
	__le32 qpn;
	__le32 rsvd2;
	__le32 rsvd3;
	__le64 to;
	__le32 length;
	__le32 stag;
};

/* SQE */
#define ERDMA_SQE_HDR_SGL_LEN_MASK GENMASK_ULL(63, 56)
#define ERDMA_SQE_HDR_WQEBB_CNT_MASK GENMASK_ULL(54, 52)
#define ERDMA_SQE_HDR_QPN_MASK GENMASK_ULL(51, 32)
#define ERDMA_SQE_HDR_OPCODE_MASK GENMASK_ULL(31, 27)
#define ERDMA_SQE_HDR_DWQE_MASK BIT_ULL(26)
#define ERDMA_SQE_HDR_INLINE_MASK BIT_ULL(25)
#define ERDMA_SQE_HDR_FENCE_MASK BIT_ULL(24)
#define ERDMA_SQE_HDR_SE_MASK BIT_ULL(23)
#define ERDMA_SQE_HDR_CE_MASK BIT_ULL(22)
#define ERDMA_SQE_HDR_WQEBB_INDEX_MASK GENMASK_ULL(15, 0)

struct erdma_write_sqe {
	__le64 hdr;
	__be32 imm_data;
	__le32 length;

	__le32 sink_stag;
	/* avoid sink_to not 8-byte aligned. */
	__le32 sink_to_low;
	__le32 sink_to_high;

	__le32 rsvd;

	struct erdma_sge sgl[];
};

struct erdma_send_sqe {
	__le64 hdr;
	__be32 imm_data;
	__le32 length;
	struct erdma_sge sgl[];
};

struct erdma_readreq_sqe {
	__le64 hdr;
	__le32 invalid_stag;
	__le32 length;
	__le32 sink_stag;
	/* avoid sink_to not 8-byte aligned. */
	__le32 sink_to_low;
	__le32 sink_to_high;
	__le32 rsvd;
	struct erdma_sge sgl;
};

struct erdma_atomic_sqe {
	__le64 hdr;
	__le64 rsvd;
	__le64 fetchadd_swap_data;
	__le64 cmp_data;

	struct erdma_sge remote;
	struct erdma_sge sgl;
};

#endif
