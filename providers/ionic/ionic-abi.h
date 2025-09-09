/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2018-2025 Advanced Micro Devices, Inc.  All rights reserved.
 */

#ifndef __IONIC_ABI_H__
#define __IONIC_ABI_H__

#include <infiniband/kern-abi.h>
#include <infiniband/verbs.h>
#include <rdma/ionic-abi.h>
#include <kernel-abi/ionic-abi.h>

#include "ionic_fw_types.h"

DECLARE_DRV_CMD(uionic_ctx, IB_USER_VERBS_CMD_GET_CONTEXT,
		ionic_ctx_req, ionic_ctx_resp);
DECLARE_DRV_CMD(uionic_ah, IB_USER_VERBS_CMD_CREATE_AH,
		empty, ionic_ah_resp);
DECLARE_DRV_CMD(uionic_cq, IB_USER_VERBS_CMD_CREATE_CQ,
		ionic_cq_req, ionic_cq_resp);
DECLARE_DRV_CMD(uionic_qp, IB_USER_VERBS_EX_CMD_CREATE_QP,
		ionic_qp_req, ionic_qp_resp);

#endif /* __IONIC_ABI_H__ */
