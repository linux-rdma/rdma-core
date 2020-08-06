/*
 * Broadcom NetXtreme-E User Space RoCE driver
 *
 * Copyright (c) 2015-2017, Broadcom. All rights reserved.  The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Description: ABI data structure definition
 */

#ifndef __BNXT_RE_ABI_H__
#define __BNXT_RE_ABI_H__

#include <infiniband/kern-abi.h>
#include <rdma/bnxt_re-abi.h>
#include <kernel-abi/bnxt_re-abi.h>

#define BNXT_RE_FULL_FLAG_DELTA        0x80

DECLARE_DRV_CMD(ubnxt_re_pd, IB_USER_VERBS_CMD_ALLOC_PD,
		empty, bnxt_re_pd_resp);
DECLARE_DRV_CMD(ubnxt_re_cq, IB_USER_VERBS_CMD_CREATE_CQ,
		bnxt_re_cq_req, bnxt_re_cq_resp);
DECLARE_DRV_CMD(ubnxt_re_qp, IB_USER_VERBS_CMD_CREATE_QP,
		bnxt_re_qp_req, bnxt_re_qp_resp);
DECLARE_DRV_CMD(ubnxt_re_cntx, IB_USER_VERBS_CMD_GET_CONTEXT,
		empty, bnxt_re_uctx_resp);
DECLARE_DRV_CMD(ubnxt_re_mr, IB_USER_VERBS_CMD_REG_MR,
		empty, empty);
DECLARE_DRV_CMD(ubnxt_re_srq, IB_USER_VERBS_CMD_CREATE_SRQ,
		bnxt_re_srq_req, bnxt_re_srq_resp);

enum bnxt_re_wr_opcode {
	BNXT_RE_WR_OPCD_SEND		= 0x00,
	BNXT_RE_WR_OPCD_SEND_IMM	= 0x01,
	BNXT_RE_WR_OPCD_SEND_INVAL	= 0x02,
	BNXT_RE_WR_OPCD_RDMA_WRITE	= 0x04,
	BNXT_RE_WR_OPCD_RDMA_WRITE_IMM	= 0x05,
	BNXT_RE_WR_OPCD_RDMA_READ	= 0x06,
	BNXT_RE_WR_OPCD_ATOMIC_CS	= 0x08,
	BNXT_RE_WR_OPCD_ATOMIC_FA	= 0x0B,
	BNXT_RE_WR_OPCD_LOC_INVAL	= 0x0C,
	BNXT_RE_WR_OPCD_BIND		= 0x0E,
	BNXT_RE_WR_OPCD_RECV		= 0x80,
	BNXT_RE_WR_OPCD_INVAL		= 0xFF
};

enum bnxt_re_wr_flags {
	BNXT_RE_WR_FLAGS_INLINE		= 0x10,
	BNXT_RE_WR_FLAGS_SE		= 0x08,
	BNXT_RE_WR_FLAGS_UC_FENCE	= 0x04,
	BNXT_RE_WR_FLAGS_RD_FENCE	= 0x02,
	BNXT_RE_WR_FLAGS_SIGNALED	= 0x01
};

enum bnxt_re_wc_type {
	BNXT_RE_WC_TYPE_SEND		= 0x00,
	BNXT_RE_WC_TYPE_RECV_RC		= 0x01,
	BNXT_RE_WC_TYPE_RECV_UD		= 0x02,
	BNXT_RE_WC_TYPE_RECV_RAW	= 0x03,
	BNXT_RE_WC_TYPE_TERM		= 0x0E,
	BNXT_RE_WC_TYPE_COFF		= 0x0F
};

enum bnxt_re_req_wc_status {
	BNXT_RE_REQ_ST_OK		= 0x00,
	BNXT_RE_REQ_ST_BAD_RESP		= 0x01,
	BNXT_RE_REQ_ST_LOC_LEN		= 0x02,
	BNXT_RE_REQ_ST_LOC_QP_OP	= 0x03,
	BNXT_RE_REQ_ST_PROT		= 0x04,
	BNXT_RE_REQ_ST_MEM_OP		= 0x05,
	BNXT_RE_REQ_ST_REM_INVAL	= 0x06,
	BNXT_RE_REQ_ST_REM_ACC		= 0x07,
	BNXT_RE_REQ_ST_REM_OP		= 0x08,
	BNXT_RE_REQ_ST_RNR_NAK_XCED	= 0x09,
	BNXT_RE_REQ_ST_TRNSP_XCED	= 0x0A,
	BNXT_RE_REQ_ST_WR_FLUSH		= 0x0B
};

enum bnxt_re_rsp_wc_status {
	BNXT_RE_RSP_ST_OK		= 0x00,
	BNXT_RE_RSP_ST_LOC_ACC		= 0x01,
	BNXT_RE_RSP_ST_LOC_LEN		= 0x02,
	BNXT_RE_RSP_ST_LOC_PROT		= 0x03,
	BNXT_RE_RSP_ST_LOC_QP_OP	= 0x04,
	BNXT_RE_RSP_ST_MEM_OP		= 0x05,
	BNXT_RE_RSP_ST_REM_INVAL	= 0x06,
	BNXT_RE_RSP_ST_WR_FLUSH		= 0x07,
	BNXT_RE_RSP_ST_HW_FLUSH		= 0x08
};

enum bnxt_re_hdr_offset {
	BNXT_RE_HDR_WT_MASK		= 0xFF,
	BNXT_RE_HDR_FLAGS_MASK		= 0xFF,
	BNXT_RE_HDR_FLAGS_SHIFT		= 0x08,
	BNXT_RE_HDR_WS_MASK		= 0xFF,
	BNXT_RE_HDR_WS_SHIFT		= 0x10
};

enum bnxt_re_db_que_type {
	BNXT_RE_QUE_TYPE_SQ		= 0x00,
	BNXT_RE_QUE_TYPE_RQ		= 0x01,
	BNXT_RE_QUE_TYPE_SRQ		= 0x02,
	BNXT_RE_QUE_TYPE_SRQ_ARM	= 0x03,
	BNXT_RE_QUE_TYPE_CQ		= 0x04,
	BNXT_RE_QUE_TYPE_CQ_ARMSE	= 0x05,
	BNXT_RE_QUE_TYPE_CQ_ARMALL	= 0x06,
	BNXT_RE_QUE_TYPE_CQ_ARMENA	= 0x07,
	BNXT_RE_QUE_TYPE_SRQ_ARMENA	= 0x08,
	BNXT_RE_QUE_TYPE_CQ_CUT_ACK	= 0x09,
	BNXT_RE_QUE_TYPE_NULL		= 0x0F
};

enum bnxt_re_db_mask {
	BNXT_RE_DB_INDX_MASK		= 0xFFFFFUL,
	BNXT_RE_DB_QID_MASK		= 0xFFFFFUL,
	BNXT_RE_DB_TYP_MASK		= 0x0FUL,
	BNXT_RE_DB_TYP_SHIFT		= 0x1C
};

enum bnxt_re_psns_mask {
	BNXT_RE_PSNS_SPSN_MASK		= 0xFFFFFF,
	BNXT_RE_PSNS_OPCD_MASK		= 0xFF,
	BNXT_RE_PSNS_OPCD_SHIFT		= 0x18,
	BNXT_RE_PSNS_NPSN_MASK		= 0xFFFFFF,
	BNXT_RE_PSNS_FLAGS_MASK		= 0xFF,
	BNXT_RE_PSNS_FLAGS_SHIFT	= 0x18
};

enum bnxt_re_bcqe_mask {
	BNXT_RE_BCQE_PH_MASK		= 0x01,
	BNXT_RE_BCQE_TYPE_MASK		= 0x0F,
	BNXT_RE_BCQE_TYPE_SHIFT		= 0x01,
	BNXT_RE_BCQE_STATUS_MASK	= 0xFF,
	BNXT_RE_BCQE_STATUS_SHIFT	= 0x08,
	BNXT_RE_BCQE_FLAGS_MASK		= 0xFFFFU,
	BNXT_RE_BCQE_FLAGS_SHIFT	= 0x10,
	BNXT_RE_BCQE_RWRID_MASK		= 0xFFFFFU,
	BNXT_RE_BCQE_SRCQP_MASK		= 0xFF,
	BNXT_RE_BCQE_SRCQP_SHIFT	= 0x18
};

enum bnxt_re_rc_flags_mask {
	BNXT_RE_RC_FLAGS_SRQ_RQ_MASK	= 0x01,
	BNXT_RE_RC_FLAGS_IMM_MASK	= 0x02,
	BNXT_RE_RC_FLAGS_IMM_SHIFT	= 0x01,
	BNXT_RE_RC_FLAGS_INV_MASK	= 0x04,
	BNXT_RE_RC_FLAGS_INV_SHIFT	= 0x02,
	BNXT_RE_RC_FLAGS_RDMA_MASK	= 0x08,
	BNXT_RE_RC_FLAGS_RDMA_SHIFT	= 0x03
};

enum bnxt_re_ud_flags_mask {
	BNXT_RE_UD_FLAGS_SRQ_RQ_MASK	= 0x01,
	BNXT_RE_UD_FLAGS_IMM_MASK	= 0x02,
	BNXT_RE_UD_FLAGS_HDR_TYP_MASK	= 0x0C,

	BNXT_RE_UD_FLAGS_SRQ		= 0x01,
	BNXT_RE_UD_FLAGS_RQ		= 0x00,
	BNXT_RE_UD_FLAGS_ROCE		= 0x00,
	BNXT_RE_UD_FLAGS_ROCE_IPV4	= 0x02,
	BNXT_RE_UD_FLAGS_ROCE_IPV6	= 0x03
};

enum bnxt_re_ud_cqe_mask {
	BNXT_RE_UD_CQE_MAC_MASK		= 0xFFFFFFFFFFFFULL,
	BNXT_RE_UD_CQE_SRCQPLO_MASK	= 0xFFFF,
	BNXT_RE_UD_CQE_SRCQPLO_SHIFT	= 0x30
};

struct bnxt_re_db_hdr {
	__le32 indx;
	__le32 typ_qid; /* typ: 4, qid:20*/
};

struct bnxt_re_bcqe {
	__le32 flg_st_typ_ph;
	__le32 qphi_rwrid;
};

struct bnxt_re_req_cqe {
	__le64 qp_handle;
	__le32 con_indx; /* 16 bits valid. */
	__le32 rsvd1;
	__le64 rsvd2;
};

struct bnxt_re_rc_cqe {
	__le32 length;
	__le32 imm_key;
	__le64 qp_handle;
	__le64 mr_handle;
};

struct bnxt_re_ud_cqe {
	__le32 length; /* 14 bits */
	__le32 immd;
	__le64 qp_handle;
	__le64 qplo_mac; /* 16:48*/
};

struct bnxt_re_term_cqe {
	__le64 qp_handle;
	__le32 rq_sq_cidx;
	__le32 rsvd;
	__le64 rsvd1;
};

struct bnxt_re_bsqe {
	__le32 rsv_ws_fl_wt;
	__le32 key_immd;
};

struct bnxt_re_psns {
	__le32 opc_spsn;
	__le32 flg_npsn;
};

struct bnxt_re_psns_ext {
	__u32 opc_spsn;
	__u32 flg_npsn;
	__u16 st_slot_idx;
	__u16 rsvd0;
	__u32 rsvd1;
};

struct bnxt_re_sge {
	__le64 pa;
	__le32 lkey;
	__le32 length;
};

/*  Cu+ max inline data */
#define BNXT_RE_MAX_INLINE_SIZE		0x60

struct bnxt_re_send {
	__le32 length;
	__le32 qkey;
	__le32 dst_qp;
	__le32 avid;
	__le64 rsvd;
};

struct bnxt_re_raw {
	__le32 length;
	__le32 rsvd1;
	__le32 cfa_meta;
	__le32 rsvd2;
	__le64 rsvd3;
};

struct bnxt_re_rdma {
	__le32 length;
	__le32 rsvd1;
	__le64 rva;
	__le32 rkey;
	__le32 rsvd2;
};

struct bnxt_re_atomic {
	__le64 rva;
	__le64 swp_dt;
	__le64 cmp_dt;
};

struct bnxt_re_inval {
	__le64 rsvd[3];
};

struct bnxt_re_bind {
	__le32 plkey;
	__le32 lkey;
	__le64 va;
	__le64 len; /* only 40 bits are valid */
};

struct bnxt_re_brqe {
	__le32 rsv_ws_fl_wt;
	__le32 rsvd;
};

struct bnxt_re_rqe {
	__le32 wrid;
	__le32 rsvd1;
	__le64 rsvd[2];
};

struct bnxt_re_srqe {
	__le32 srq_tag; /* 20 bits are valid */
	__le32 rsvd1;
	__le64 rsvd[2];
};
#endif
