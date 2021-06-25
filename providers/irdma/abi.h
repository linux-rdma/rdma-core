/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (C) 2019 - 2020 Intel Corporation */
#ifndef PROVIDER_IRDMA_ABI_H
#define PROVIDER_IRDMA_ABI_H

#include "irdma.h"
#include <infiniband/kern-abi.h>
#include <rdma/irdma-abi.h>
#include <kernel-abi/irdma-abi.h>

#define IRDMA_MIN_ABI_VERSION	0
#define IRDMA_MAX_ABI_VERSION	5

DECLARE_DRV_CMD(irdma_ualloc_pd, IB_USER_VERBS_CMD_ALLOC_PD,
		empty, irdma_alloc_pd_resp);
DECLARE_DRV_CMD(irdma_ucreate_cq, IB_USER_VERBS_CMD_CREATE_CQ,
		irdma_create_cq_req, irdma_create_cq_resp);
DECLARE_DRV_CMD(irdma_ucreate_cq_ex, IB_USER_VERBS_EX_CMD_CREATE_CQ,
		irdma_create_cq_req, irdma_create_cq_resp);
DECLARE_DRV_CMD(irdma_uresize_cq, IB_USER_VERBS_CMD_RESIZE_CQ,
		irdma_resize_cq_req, empty);
DECLARE_DRV_CMD(irdma_ucreate_qp, IB_USER_VERBS_CMD_CREATE_QP,
		irdma_create_qp_req, irdma_create_qp_resp);
DECLARE_DRV_CMD(irdma_umodify_qp, IB_USER_VERBS_EX_CMD_MODIFY_QP,
		irdma_modify_qp_req, irdma_modify_qp_resp);
DECLARE_DRV_CMD(irdma_get_context, IB_USER_VERBS_CMD_GET_CONTEXT,
		irdma_alloc_ucontext_req, irdma_alloc_ucontext_resp);
DECLARE_DRV_CMD(irdma_ureg_mr, IB_USER_VERBS_CMD_REG_MR,
		irdma_mem_reg_req, empty);
DECLARE_DRV_CMD(irdma_ucreate_ah, IB_USER_VERBS_CMD_CREATE_AH,
		empty, irdma_create_ah_resp);

#endif /* PROVIDER_IRDMA_ABI_H */
