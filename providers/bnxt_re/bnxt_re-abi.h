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

#define BNXT_RE_ABI_VERSION 1

struct bnxt_re_cntx_resp {
	struct ibv_get_context_resp resp;
	__u32 dev_id;
	__u32 max_qp; /* To allocate qp-table */
	__u32 pg_size;
	__u32 cqe_size;
	__u32 max_cqd;
	__u32 rsvd;
};

struct bnxt_re_pd_resp {
	struct ibv_alloc_pd_resp resp;
	__u32 pdid;
	__u32 dpi;
	__u64 dbr;
};

struct bnxt_re_mr_resp {
	struct ibv_reg_mr_resp resp;
};

struct bnxt_re_cq_req {
	struct ibv_create_cq cmd;
	__u64 cq_va;
	__u64 cq_handle;
};

struct bnxt_re_cq_resp {
	struct ibv_create_cq_resp resp;
	__u32 cqid;
	__u32 tail;
	__u32 phase;
	__u32 rsvd;
};

struct bnxt_re_qp_req {
	struct ibv_create_qp cmd;
	__u64 qpsva;
	__u64 qprva;
	__u64 qp_handle;
};

struct bnxt_re_qp_resp {
	struct ibv_create_qp_resp resp;
	__u32 qpid;
	__u32 rsvd;
};

struct bnxt_re_bsqe {
	__le32 rsv_ws_fl_wt;
	__le32 key_immd;
};

struct bnxt_re_psns {
	__le32 opc_spsn;
	__le32 flg_npsn;
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
	__le64 rsvd[3];
};

struct bnxt_re_srqe {
	__le32 srq_tag; /* 20 bits are valid */
	__le32 rsvd1;
	__le64 rsvd[2];
};

#endif
