/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_ABI_H
#define XSC_ABI_H

#include <infiniband/kern-abi.h>
#include <infiniband/verbs.h>
#include <rdma/xsc-abi.h>
#include <kernel-abi/xsc-abi.h>

#define XSC_UVERBS_MIN_ABI_VERSION 1
#define XSC_UVERBS_MAX_ABI_VERSION 1

DECLARE_DRV_CMD(xsc_alloc_ucontext, IB_USER_VERBS_CMD_GET_CONTEXT,
		empty, xsc_ib_alloc_ucontext_resp);
DECLARE_DRV_CMD(xsc_alloc_pd, IB_USER_VERBS_CMD_ALLOC_PD, empty,
		xsc_ib_alloc_pd_resp);
DECLARE_DRV_CMD(xsc_create_cq, IB_USER_VERBS_CMD_CREATE_CQ, xsc_ib_create_cq,
		xsc_ib_create_cq_resp);
DECLARE_DRV_CMD(xsc_create_cq_ex, IB_USER_VERBS_EX_CMD_CREATE_CQ,
		xsc_ib_create_cq, xsc_ib_create_cq_resp);
DECLARE_DRV_CMD(xsc_create_qp_ex, IB_USER_VERBS_EX_CMD_CREATE_QP,
		xsc_ib_create_qp, xsc_ib_create_qp_resp);
DECLARE_DRV_CMD(xsc_create_qp, IB_USER_VERBS_CMD_CREATE_QP, xsc_ib_create_qp,
		xsc_ib_create_qp_resp);

#endif /* XSC_ABI_H */
