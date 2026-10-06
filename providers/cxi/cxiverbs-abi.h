/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright 2025 HPE. All rights reserved.
 */

#ifndef __CXI_ABI_H__
#define __CXI_ABI_H__

#include <infiniband/kern-abi.h>
#include <kernel-abi/cxiverbs-abi.h>
#include <rdma/cxiverbs-abi.h>

DECLARE_DRV_CMD(cxi_alloc_ucontext, IB_USER_VERBS_CMD_GET_CONTEXT, cxi_ibv_alloc_ucontext_cmd,
		cxi_ibv_alloc_ucontext_resp);
DECLARE_DRV_CMD(cxi_alloc_pd, IB_USER_VERBS_CMD_ALLOC_PD, cxi_ibv_alloc_pd_cmd,
		cxi_ibv_alloc_pd_resp);
DECLARE_DRV_CMD(cxi_create_cq, IB_USER_VERBS_CMD_CREATE_CQ, cxi_ibv_create_cq_cmd,
		cxi_ibv_create_cq_resp);
DECLARE_DRV_CMD(cxi_create_cq_ex, IB_USER_VERBS_EX_CMD_CREATE_CQ, cxi_ibv_create_cq_cmd,
		cxi_ibv_create_cq_resp);
DECLARE_DRV_CMD(cxi_create_qp, IB_USER_VERBS_CMD_CREATE_QP, cxi_ibv_create_qp_cmd,
		cxi_ibv_create_qp_resp);
DECLARE_DRV_CMD(cxi_create_qp_ex, IB_USER_VERBS_EX_CMD_CREATE_QP, cxi_ibv_create_qp_cmd,
		cxi_ibv_create_qp_resp);
DECLARE_DRV_CMD(cxi_modify_qp_ex, IB_USER_VERBS_EX_CMD_MODIFY_QP, empty, cxi_ibv_modify_qp_resp);
DECLARE_DRV_CMD(cxi_reg_mr, IB_USER_VERBS_CMD_REG_MR, cxi_ibv_reg_mr, cxi_ibv_reg_mr_resp);
DECLARE_DRV_CMD(cxi_query_device_ex, IB_USER_VERBS_EX_CMD_QUERY_DEVICE, empty,
		cxi_ibv_query_device_resp);
#endif /* __CXI_ABI_H__ */
