/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#ifndef __EFA_ABI_H__
#define __EFA_ABI_H__

#include <infiniband/kern-abi.h>
#include <kernel-abi/efa-abi.h>
#include <rdma/efa-abi.h>

#define EFA_ABI_VERSION 1

DECLARE_DRV_CMD(efa_alloc_ucontext, IB_USER_VERBS_CMD_GET_CONTEXT, empty,
		efa_ibv_alloc_ucontext_resp);
DECLARE_DRV_CMD(efa_alloc_pd, IB_USER_VERBS_CMD_ALLOC_PD, empty,
		efa_ibv_alloc_pd_resp);
DECLARE_DRV_CMD(efa_create_cq, IB_USER_VERBS_CMD_CREATE_CQ, efa_ibv_create_cq,
		efa_ibv_create_cq_resp);
DECLARE_DRV_CMD(efa_create_qp, IB_USER_VERBS_CMD_CREATE_QP, efa_ibv_create_qp,
		efa_ibv_create_qp_resp);
DECLARE_DRV_CMD(efa_create_ah, IB_USER_VERBS_CMD_CREATE_AH, empty,
		efa_ibv_create_ah_resp);
DECLARE_DRV_CMD(efa_query_device_ex, IB_USER_VERBS_EX_CMD_QUERY_DEVICE, empty,
		efa_ibv_ex_query_device_resp);

#endif /* __EFA_ABI_H__ */
