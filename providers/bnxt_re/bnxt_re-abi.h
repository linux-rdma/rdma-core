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

DECLARE_DRV_CMD(ubnxt_re_pd, IB_USER_VERBS_CMD_ALLOC_PD,
		empty, bnxt_re_pd_resp);
DECLARE_DRV_CMD(ubnxt_re_cq, IB_USER_VERBS_CMD_CREATE_CQ,
		bnxt_re_cq_req, bnxt_re_cq_resp);
DECLARE_DRV_CMD(ubnxt_re_resize_cq, IB_USER_VERBS_CMD_RESIZE_CQ,
		bnxt_re_resize_cq_req, empty);
DECLARE_DRV_CMD(ubnxt_re_qp, IB_USER_VERBS_CMD_CREATE_QP,
		bnxt_re_qp_req, bnxt_re_qp_resp);
DECLARE_DRV_CMD(ubnxt_re_cntx, IB_USER_VERBS_CMD_GET_CONTEXT,
		bnxt_re_uctx_req, bnxt_re_uctx_resp);
DECLARE_DRV_CMD(ubnxt_re_mr, IB_USER_VERBS_CMD_REG_MR,
		empty, empty);
DECLARE_DRV_CMD(ubnxt_re_srq, IB_USER_VERBS_CMD_CREATE_SRQ,
		bnxt_re_srq_req, bnxt_re_srq_resp);
DECLARE_DRV_CMD(ubnxt_re_query_device_ex, IB_USER_VERBS_EX_CMD_QUERY_DEVICE,
		empty, bnxt_re_query_device_ex_resp);
#endif
