/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2018-2025 Advanced Micro Devices, Inc.  All rights reserved.
 */

#ifndef IONIC_FW_TYPES_H
#define IONIC_FW_TYPES_H

#define IONIC_EXP_DBELL_SZ 8

/* common to all versions */

/* wqe scatter gather element */
struct ionic_sge {
	__be64				va;
	__be32				len;
	__be32				lkey;
};

/* admin queue mr type */
enum ionic_mr_flags {
	/* bits that determine mr access */
	IONIC_MRF_LOCAL_WRITE		= 1u << 0,
	IONIC_MRF_REMOTE_WRITE		= 1u << 1,
	IONIC_MRF_REMOTE_READ		= 1u << 2,
	IONIC_MRF_REMOTE_ATOMIC		= 1u << 3,
	IONIC_MRF_MW_BIND		= 1u << 4,
	IONIC_MRF_ZERO_BASED		= 1u << 5,
	IONIC_MRF_ON_DEMAND		= 1u << 6,
	IONIC_MRF_PB			= 1u << 7,
	IONIC_MRF_ACCESS_MASK		= (1u << 12) - 1,

	/* bits that determine mr type */
	IONIC_MRF_IS_MW			= 1u << 14,
	IONIC_MRF_INV_EN		= 1u << 15,

	/* base flags combinations for mr types */
	IONIC_MRF_USER_MR		= 0,
	IONIC_MRF_PHYS_MR		= IONIC_MRF_INV_EN,
	IONIC_MRF_MW_1			= IONIC_MRF_IS_MW,
	IONIC_MRF_MW_2			= IONIC_MRF_IS_MW | IONIC_MRF_INV_EN,
};

/* cqe status indicated in status_length field when err bit is set */
enum ionic_status {
	IONIC_STS_OK,
	IONIC_STS_LOCAL_LEN_ERR,
	IONIC_STS_LOCAL_QP_OPER_ERR,
	IONIC_STS_LOCAL_PROT_ERR,
	IONIC_STS_WQE_FLUSHED_ERR,
	IONIC_STS_MEM_MGMT_OPER_ERR,
	IONIC_STS_BAD_RESP_ERR,
	IONIC_STS_LOCAL_ACC_ERR,
	IONIC_STS_REMOTE_INV_REQ_ERR,
	IONIC_STS_REMOTE_ACC_ERR,
	IONIC_STS_REMOTE_OPER_ERR,
	IONIC_STS_RETRY_EXCEEDED,
	IONIC_STS_RNR_RETRY_EXCEEDED,
	IONIC_STS_XRC_VIO_ERR,
};


/* fw abi v1 */

/* data payload part of v1 wqe */
union ionic_v1_pld {
	struct ionic_sge	sgl[2];
	__be32			spec32[8];
	__be16			spec16[16];
	__u8			data[32];
};

/* completion queue v1 cqe */
struct ionic_v1_cqe {
	union {
		struct {
			__le64		wqe_idx;
			__be32		src_qpn_op;
			__u8		src_mac[6];
			__be16		vlan_tag;
			__be32		imm_data_rkey;
		} recv;
		struct {
			__u8		rsvd[4];
			__be32		msg_msn;
			__u8		rsvd2[8];
			__le64		npg_wqe_idx;
		} send;
	};
	__be32				status_length;
	__be32				qid_type_flags;
};

/* bits for cqe wqe_idx */
enum ionic_v1_cqe_wqe_idx_bits {
	IONIC_V1_CQE_WQE_IDX_MASK	= 0xffff,
};

/* bits for cqe recv */
enum ionic_v1_cqe_src_qpn_bits {
	IONIC_V1_CQE_RECV_QPN_MASK	= 0xffffff,
	IONIC_V1_CQE_RECV_OP_SHIFT	= 24,

	/* MASK could be 0x3, but need 0x1f for makeshift values:
	 * OP_TYPE_RDMA_OPER_WITH_IMM, OP_TYPE_SEND_RCVD
	 */
	IONIC_V1_CQE_RECV_OP_MASK	= 0x1f,
	IONIC_V1_CQE_RECV_OP_SEND	= 0,
	IONIC_V1_CQE_RECV_OP_SEND_INV	= 1,
	IONIC_V1_CQE_RECV_OP_SEND_IMM	= 2,
	IONIC_V1_CQE_RECV_OP_RDMA_IMM	= 3,

	IONIC_V1_CQE_RECV_IS_IPV4	= 1u << (7 + IONIC_V1_CQE_RECV_OP_SHIFT),
	IONIC_V1_CQE_RECV_IS_VLAN	= 1u << (6 + IONIC_V1_CQE_RECV_OP_SHIFT),
};

/* bits for cqe qid_type_flags */
enum ionic_v1_cqe_qtf_bits {
	IONIC_V1_CQE_COLOR		= 1u << 0,
	IONIC_V1_CQE_ERROR		= 1u << 1,
	IONIC_V1_CQE_TYPE_SHIFT		= 5,
	IONIC_V1_CQE_TYPE_MASK		= 0x7,
	IONIC_V1_CQE_QID_SHIFT		= 8,

	IONIC_V1_CQE_TYPE_RECV		= 1,
	IONIC_V1_CQE_TYPE_SEND_MSN	= 2,
	IONIC_V1_CQE_TYPE_SEND_NPG	= 3,
	IONIC_V1_CQE_TYPE_RECV_INDIR	= 4,
};

/* v1 base wqe header */
struct ionic_v1_base_hdr {
	__le64				wqe_idx;
	__u8				op;
	__u8				num_sge_key;
	__be16				flags;
	__be32				imm_data_key;
};

/* v1 receive wqe body */
struct ionic_v1_recv_bdy {
	__u8				rsvd[16];
	union ionic_v1_pld		pld;
};

/* v1 send/rdma wqe body (common, has sgl) */
struct ionic_v1_common_bdy {
	union {
		struct {
			__be32		ah_id;
			__be32		dest_qpn;
			__be32		dest_qkey;
		} send;
		struct {
			__be32		remote_va_high;
			__be32		remote_va_low;
			__be32		remote_rkey;
		} rdma;
	};
	__be32				length;
	union ionic_v1_pld		pld;
};

/* v1 atomic wqe body */
struct ionic_v1_atomic_bdy {
	__be32				remote_va_high;
	__be32				remote_va_low;
	__be32				remote_rkey;
	__be32				swap_add_high;
	__be32				swap_add_low;
	__be32				compare_high;
	__be32				compare_low;
	__u8				rsvd[4];
	struct ionic_sge		sge;
};

/* v2 atomic wqe body */
struct ionic_v2_atomic_bdy {
	__be32				remote_va_high;
	__be32				remote_va_low;
	__be32				remote_rkey;
	__be32				swap_add_high;
	__be32				swap_add_low;
	__be32				compare_high;
	__be32				compare_low;
	__be32				lkey;
	__be64				local_va;
	__u8				rsvd_expdb[8];
};

/* v1 bind mw wqe body */
struct ionic_v1_bind_mw_bdy {
	__be64				va;
	__be64				length;
	__be32				lkey;
	__be16				flags;
	__u8				rsvd[26];
};

/* v1 send/recv wqe */
struct ionic_v1_wqe {
	struct ionic_v1_base_hdr	base;
	union {
		struct ionic_v1_recv_bdy	recv;
		struct ionic_v1_common_bdy	common;
		struct ionic_v1_atomic_bdy	atomic;
		struct ionic_v2_atomic_bdy	atomic_v2;
		struct ionic_v1_bind_mw_bdy	bind_mw;
	};
};

/* queue pair v1 send opcodes */
enum ionic_v1_op {
	IONIC_V1_OP_SEND,
	IONIC_V1_OP_SEND_INV,
	IONIC_V1_OP_SEND_IMM,
	IONIC_V1_OP_RDMA_READ,
	IONIC_V1_OP_RDMA_WRITE,
	IONIC_V1_OP_RDMA_WRITE_IMM,
	IONIC_V1_OP_ATOMIC_CS,
	IONIC_V1_OP_ATOMIC_FA,
	IONIC_V1_OP_REG_MR,
	IONIC_V1_OP_LOCAL_INV,
	IONIC_V1_OP_BIND_MW,

	/* flags */
	IONIC_V1_FLAG_FENCE		= 1u << 0,
	IONIC_V1_FLAG_SOL		= 1u << 1,
	IONIC_V1_FLAG_INL		= 1u << 2,
	IONIC_V1_FLAG_SIG		= 1u << 3,
	IONIC_V1_FLAG_COLOR		= 1u << 4,

	/* flags last four bits for sgl spec format */
	IONIC_V1_FLAG_SPEC32		= (1u << 12),
	IONIC_V1_FLAG_SPEC16		= (2u << 12),
	IONIC_V1_SPEC_FIRST_SGE		= 2,
};

/* queue pair v2 send opcodes */
enum ionic_v2_op {
	IONIC_V2_OPSL_OUT               = 0x20,
	IONIC_V2_OPSL_IMM               = 0x40,
	IONIC_V2_OPSL_INV               = 0x80,

	IONIC_V2_OP_SEND                = 0x0 | IONIC_V2_OPSL_OUT,
	IONIC_V2_OP_SEND_IMM            = IONIC_V2_OP_SEND | IONIC_V2_OPSL_IMM,
	IONIC_V2_OP_SEND_INV            = IONIC_V2_OP_SEND | IONIC_V2_OPSL_INV,

	IONIC_V2_OP_RDMA_WRITE          = 0x1 | IONIC_V2_OPSL_OUT,
	IONIC_V2_OP_RDMA_WRITE_IMM      = IONIC_V2_OP_RDMA_WRITE | IONIC_V2_OPSL_IMM,

	IONIC_V2_OP_RDMA_READ           = 0x2,

	IONIC_V2_OP_ATOMIC_CS           = 0x4,
	IONIC_V2_OP_ATOMIC_FA           = 0x5,
	IONIC_V2_OP_REG_MR              = 0x6,
	IONIC_V2_OP_LOCAL_INV           = 0x7,
	IONIC_V2_OP_BIND_MW             = 0x8,
};

#endif /* IONIC_FW_TYPES_H */
