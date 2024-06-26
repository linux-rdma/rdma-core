/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright 2022-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#ifndef HBL_IB_ABI_H
#define HBL_IB_ABI_H

#include <infiniband/kern-abi.h>
#include <kernel-abi/hbl-abi.h>
#include <rdma/hbl-abi.h>

#define HBL_IB_ABI_VERSION 1

DECLARE_DRV_CMD(hbl_alloc_ucontext, IB_USER_VERBS_CMD_GET_CONTEXT, hbl_ibv_alloc_ucontext_req,
		hbl_ibv_alloc_ucontext_resp);
DECLARE_DRV_CMD(hbl_alloc_pd, IB_USER_VERBS_CMD_ALLOC_PD, empty, hbl_ibv_alloc_pd_resp);
DECLARE_DRV_CMD(hbl_modify_qp, IB_USER_VERBS_EX_CMD_MODIFY_QP,
		hbl_ibv_modify_qp_req, hbl_ibv_modify_qp_resp);
DECLARE_DRV_CMD(hbl_create_cq, IB_USER_VERBS_CMD_CREATE_CQ, hbl_ibv_create_cq_req,
		hbl_ibv_create_cq_resp);

#endif /* HBL_IB_ABI_H */
