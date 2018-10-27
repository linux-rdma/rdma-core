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

#ifndef _HNS_ROCE_U_ABI_H
#define _HNS_ROCE_U_ABI_H

#include <infiniband/kern-abi.h>
#include <rdma/hns-abi.h>
#include <kernel-abi/hns-abi.h>

DECLARE_DRV_CMD(hns_roce_alloc_pd, IB_USER_VERBS_CMD_ALLOC_PD,
		empty, hns_roce_ib_alloc_pd_resp);
DECLARE_DRV_CMD(hns_roce_create_cq, IB_USER_VERBS_CMD_CREATE_CQ,
		hns_roce_ib_create_cq, hns_roce_ib_create_cq_resp);
DECLARE_DRV_CMD(hns_roce_create_qp, IB_USER_VERBS_CMD_CREATE_QP,
		hns_roce_ib_create_qp, hns_roce_ib_create_qp_resp);
DECLARE_DRV_CMD(hns_roce_alloc_ucontext, IB_USER_VERBS_CMD_GET_CONTEXT,
		empty, hns_roce_ib_alloc_ucontext_resp);

DECLARE_DRV_CMD(hns_roce_create_srq, IB_USER_VERBS_CMD_CREATE_SRQ,
		hns_roce_ib_create_srq, hns_roce_ib_create_srq_resp);

#endif /* _HNS_ROCE_U_ABI_H */
