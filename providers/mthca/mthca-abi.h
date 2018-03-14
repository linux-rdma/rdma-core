/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2006 Cisco Systems.  All rights reserved.
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

#ifndef MTHCA_ABI_H
#define MTHCA_ABI_H

#include <infiniband/kern-abi.h>
#include <rdma/mthca-abi.h>
#include <kernel-abi/mthca-abi.h>

DECLARE_DRV_CMD(umthca_alloc_pd, IB_USER_VERBS_CMD_ALLOC_PD,
		empty, mthca_alloc_pd_resp);
DECLARE_DRV_CMD(umthca_create_cq, IB_USER_VERBS_CMD_CREATE_CQ,
		mthca_create_cq, mthca_create_cq_resp);
DECLARE_DRV_CMD(umthca_create_qp, IB_USER_VERBS_CMD_CREATE_QP,
		mthca_create_qp, empty);
DECLARE_DRV_CMD(umthca_create_srq, IB_USER_VERBS_CMD_CREATE_SRQ,
		mthca_create_srq, mthca_create_srq_resp);
DECLARE_DRV_CMD(umthca_alloc_ucontext, IB_USER_VERBS_CMD_GET_CONTEXT,
		empty, mthca_alloc_ucontext_resp);
DECLARE_DRV_CMD(umthca_reg_mr, IB_USER_VERBS_CMD_REG_MR,
		mthca_reg_mr, empty);
DECLARE_DRV_CMD(umthca_resize_cq, IB_USER_VERBS_CMD_RESIZE_CQ,
		mthca_resize_cq, empty);

#endif /* MTHCA_ABI_H */
