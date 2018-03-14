/*
 * Copyright (C) 2008-2013 Emulex.  All rights reserved.
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT  LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR  A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __OCRDMA_ABI_H__
#define __OCRDMA_ABI_H__

#include <stdint.h>
#include <infiniband/kern-abi.h>
#include <rdma/ocrdma-abi.h>
#include <kernel-abi/ocrdma-abi.h>

#define OCRDMA_ABI_VERSION	2

DECLARE_DRV_CMD(uocrdma_get_context, IB_USER_VERBS_CMD_GET_CONTEXT,
		empty, ocrdma_alloc_ucontext_resp);
DECLARE_DRV_CMD(uocrdma_alloc_pd, IB_USER_VERBS_CMD_ALLOC_PD,
		ocrdma_alloc_pd_ureq, ocrdma_alloc_pd_uresp);
DECLARE_DRV_CMD(uocrdma_create_cq, IB_USER_VERBS_CMD_CREATE_CQ,
		ocrdma_create_cq_ureq, ocrdma_create_cq_uresp);
DECLARE_DRV_CMD(uocrdma_reg_mr, IB_USER_VERBS_CMD_REG_MR,
		empty, empty);
DECLARE_DRV_CMD(uocrdma_create_qp, IB_USER_VERBS_CMD_CREATE_QP,
		ocrdma_create_qp_ureq, ocrdma_create_qp_uresp);
DECLARE_DRV_CMD(uocrdma_create_srq, IB_USER_VERBS_CMD_CREATE_SRQ,
		empty, ocrdma_create_srq_uresp);

#define Bit(_b) (1 << (_b))

#define OCRDMA_MAX_QP    2048

enum {
	OCRDMA_DB_RQ_OFFSET 		= 0xE0,
	OCRDMA_DB_SQ_OFFSET 		= 0x60,
	OCRDMA_DB_SRQ_OFFSET 		= OCRDMA_DB_RQ_OFFSET,
	OCRDMA_DB_CQ_OFFSET 		= 0x120
};

#define OCRDMA_DB_CQ_RING_ID_MASK		0x3FF	/* bits 0 - 9 */
#define OCRDMA_DB_CQ_RING_ID_EXT_MASK		0x0C00	/* bits 10-11 of qid placing at 12-11 */
#define OCRDMA_DB_CQ_RING_ID_EXT_MASK_SHIFT	0x1	/* qid #2 msbits placing at 12-11 */
#define OCRDMA_DB_CQ_NUM_POPPED_SHIFT		(16)	/* bits 16 - 28 */
/* Rearm bit */
#define OCRDMA_DB_CQ_REARM_SHIFT		(29)	/* bit 29 */

/* solicited bit */
#define OCRDMA_DB_CQ_SOLICIT_SHIFT		(31)	/* bit 31 */

enum OCRDMA_CQE_STATUS {
	OCRDMA_CQE_SUCCESS 		= 0,
	OCRDMA_CQE_LOC_LEN_ERR 		= 1,
	OCRDMA_CQE_LOC_QP_OP_ERR 	= 2,
	OCRDMA_CQE_LOC_EEC_OP_ERR 	= 3,
	OCRDMA_CQE_LOC_PROT_ERR 	= 4,
	OCRDMA_CQE_WR_FLUSH_ERR 	= 5,
	OCRDMA_CQE_MW_BIND_ERR 		= 6,
	OCRDMA_CQE_BAD_RESP_ERR 	= 7,
	OCRDMA_CQE_LOC_ACCESS_ERR 	= 8,
	OCRDMA_CQE_REM_INV_REQ_ERR 	= 9,
	OCRDMA_CQE_REM_ACCESS_ERR 	= 0xa,
	OCRDMA_CQE_REM_OP_ERR 		= 0xb,
	OCRDMA_CQE_RETRY_EXC_ERR 	= 0xc,
	OCRDMA_CQE_RNR_RETRY_EXC_ERR 	= 0xd,
	OCRDMA_CQE_LOC_RDD_VIOL_ERR 	= 0xe,
	OCRDMA_CQE_REM_INV_RD_REQ_ERR 	= 0xf,
	OCRDMA_CQE_REM_ABORT_ERR 	= 0x10,
	OCRDMA_CQE_INV_EECN_ERR 	= 0x11,
	OCRDMA_CQE_INV_EEC_STATE_ERR 	= 0x12,
	OCRDMA_CQE_FATAL_ERR 		= 0x13,
	OCRDMA_CQE_RESP_TIMEOUT_ERR 	= 0x14,
	OCRDMA_CQE_GENERAL_ERR
};

enum {
	/* w0 */
	OCRDMA_CQE_WQEIDX_SHIFT 	= 0,
	OCRDMA_CQE_WQEIDX_MASK 		= 0xFFFF,

	/* w1 */
	OCRDMA_CQE_UD_XFER_LEN_SHIFT 	= 16,
	OCRDMA_CQE_PKEY_SHIFT 		= 0,
	OCRDMA_CQE_PKEY_MASK 		= 0xFFFF,

	/* w2 */
	OCRDMA_CQE_QPN_SHIFT 		= 0,
	OCRDMA_CQE_QPN_MASK 		= 0x0000FFFF,

	OCRDMA_CQE_BUFTAG_SHIFT 	= 16,
	OCRDMA_CQE_BUFTAG_MASK 		= 0xFFFF << OCRDMA_CQE_BUFTAG_SHIFT,

	/* w3 */
	OCRDMA_CQE_UD_STATUS_SHIFT 	= 24,
	OCRDMA_CQE_UD_STATUS_MASK 	= 0x7 << OCRDMA_CQE_UD_STATUS_SHIFT,
	OCRDMA_CQE_STATUS_SHIFT 	= 16,
	OCRDMA_CQE_STATUS_MASK 		= (0xFF << OCRDMA_CQE_STATUS_SHIFT),
	OCRDMA_CQE_VALID 		= Bit(31),
	OCRDMA_CQE_INVALIDATE 		= Bit(30),
	OCRDMA_CQE_QTYPE 		= Bit(29),
	OCRDMA_CQE_IMM 			= Bit(28),
	OCRDMA_CQE_WRITE_IMM 		= Bit(27),
	OCRDMA_CQE_QTYPE_SQ 		= 0,
	OCRDMA_CQE_QTYPE_RQ 		= 1,
	OCRDMA_CQE_SRCQP_MASK 		= 0xFFFFFF
};

struct ocrdma_cqe {
	union {
		/* w0 to w2 */
		struct {
			__le32 wqeidx;
			__le32 bytes_xfered;
			__le32 qpn;
		} wq;
		struct {
			__le32 lkey_immdt;
			__le32 rxlen;
			__le32 buftag_qpn;
		} rq;
		struct {
			__le32 lkey_immdt;
			__le32 rxlen_pkey;
			__le32 buftag_qpn;
		} ud;
		struct {
			__le32 word_0;
			__le32 word_1;
			__le32 qpn;
		} cmn;
	};
	__le32 flags_status_srcqpn;	/* w3 */
} __attribute__ ((packed));

struct ocrdma_sge {
	uint32_t addr_hi;
	uint32_t addr_lo;
	uint32_t lrkey;
	uint32_t len;
} __attribute__ ((packed));

enum {
	OCRDMA_WQE_OPCODE_SHIFT 	= 0,
	OCRDMA_WQE_OPCODE_MASK 		= 0x0000001F,
	OCRDMA_WQE_FLAGS_SHIFT 		= 5,
	OCRDMA_WQE_TYPE_SHIFT 		= 16,
	OCRDMA_WQE_TYPE_MASK 		= 0x00030000,
	OCRDMA_WQE_SIZE_SHIFT 		= 18,
	OCRDMA_WQE_SIZE_MASK 		= 0xFF,
	OCRDMA_WQE_NXT_WQE_SIZE_SHIFT 	= 25,
	OCRDMA_WQE_LKEY_FLAGS_SHIFT 	= 0,
	OCRDMA_WQE_LKEY_FLAGS_MASK 	= 0xF
};

enum {
	OCRDMA_FLAG_SIG 	= 0x1,
	OCRDMA_FLAG_INV 	= 0x2,
	OCRDMA_FLAG_FENCE_L 	= 0x4,
	OCRDMA_FLAG_FENCE_R 	= 0x8,
	OCRDMA_FLAG_SOLICIT	= 0x10,
	OCRDMA_FLAG_IMM 	= 0x20,
	OCRDMA_FLAG_AH_VLAN_PR	= 0x40,

	/* Stag flags */
	OCRDMA_LKEY_FLAG_LOCAL_WR 	= 0x1,
	OCRDMA_LKEY_FLAG_REMOTE_RD 	= 0x2,
	OCRDMA_LKEY_FLAG_REMOTE_WR 	= 0x4,
	OCRDMA_LKEY_FLAG_VATO 		= 0x8
};

enum {
	OCRDMA_TYPE_INLINE 	= 0x0,
	OCRDMA_TYPE_LKEY 	= 0x1
};

#define OCRDMA_CQE_QTYPE_RQ  1
#define OCRDMA_CQE_QTYPE_SQ  0

enum OCRDMA_WQE_OPCODE {
	OCRDMA_WRITE 		= 0x06,
	OCRDMA_READ 		= 0x0C,
	OCRDMA_RESV0 		= 0x02,
	OCRDMA_SEND 		= 0x00,
	OCRDMA_BIND_MW 		= 0x08,
	OCRDMA_RESV1 		= 0x0A,
	OCRDMA_LKEY_INV 	= 0x15,
};

#define OCRDMA_WQE_STRIDE 8
#define OCRDMA_WQE_ALIGN_BYTES 16
/* header WQE for all the SQ and RQ operations */
struct ocrdma_hdr_wqe {
	uint32_t cw;
	union {
		uint32_t rsvd_tag;
		uint32_t rsvd_stag_flags;
	};
	union {
		uint32_t immdt;
		uint32_t lkey;
	};
	uint32_t total_len;
} __attribute__ ((packed));

struct ocrdma_hdr_wqe_le {
	__le32 cw;
	union {
		__le32 rsvd_tag;
		__le32 rsvd_stag_flags;
	};
	union {
		__le32 immdt;
		__le32 lkey;
	};
	__le32 total_len;
} __attribute__ ((packed));

struct ocrdma_ewqe_atomic {
	uint32_t ra_hi;
	uint32_t ra_lo;
	uint32_t rkey;
	uint32_t rlen;
	uint32_t swap_add_hi;
	uint32_t swap_add_lo;
	uint32_t compare_hi;
	uint32_t compare_lo;
	struct ocrdma_sge sge;
} __attribute__ ((packed));

struct ocrdma_ewqe_ud_hdr {
	uint32_t rsvd_dest_qpn;
	uint32_t qkey;
	uint32_t rsvd_ahid;
	uint32_t hdr_type;
} __attribute__ ((packed));

#endif				/* __OCRDMA_ABI_H__ */
