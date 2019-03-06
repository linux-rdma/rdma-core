/*
 * Copyright (c) 2015-2016  QLogic Corporation
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
 *        disclaimer in the documentation and /or other materials
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

#ifndef __QELR_ABI_H__
#define __QELR_ABI_H__

#include <infiniband/kern-abi.h>
#include <rdma/qedr-abi.h>
#include <kernel-abi/qedr-abi.h>

#define QELR_ABI_VERSION			(8)

DECLARE_DRV_CMD(qelr_alloc_pd, IB_USER_VERBS_CMD_ALLOC_PD,
		empty, qedr_alloc_pd_uresp);
DECLARE_DRV_CMD(qelr_create_cq, IB_USER_VERBS_CMD_CREATE_CQ,
		qedr_create_cq_ureq, qedr_create_cq_uresp);
DECLARE_DRV_CMD(qelr_create_qp, IB_USER_VERBS_CMD_CREATE_QP,
		qedr_create_qp_ureq, qedr_create_qp_uresp);
DECLARE_DRV_CMD(qelr_alloc_context, IB_USER_VERBS_CMD_GET_CONTEXT,
		qedr_alloc_ucontext_req, qedr_alloc_ucontext_resp);
DECLARE_DRV_CMD(qelr_reg_mr, IB_USER_VERBS_CMD_REG_MR,
		empty, empty);
DECLARE_DRV_CMD(qelr_create_srq, IB_USER_VERBS_CMD_CREATE_SRQ,
		qedr_create_srq_ureq, qedr_create_srq_uresp);

#endif /* __QELR_ABI_H__ */
