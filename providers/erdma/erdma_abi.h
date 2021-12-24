/* SPDX-License-Identifier: GPL-2.0 or OpenIB.org BSD (MIT) See COPYING file */
/*
 * Authors: Cheng Xu <chengyou@linux.alibaba.com>
 * Copyright (c) 2020-2021, Alibaba Group.
 */

#ifndef __ERDMA_ABI_H__
#define __ERDMA_ABI_H__

#include <infiniband/kern-abi.h>
#include <rdma/erdma-abi.h>
#include <kernel-abi/erdma-abi.h>

DECLARE_DRV_CMD(erdma_cmd_alloc_context, IB_USER_VERBS_CMD_GET_CONTEXT, empty,
		erdma_uresp_alloc_ctx);
DECLARE_DRV_CMD(erdma_cmd_create_cq, IB_USER_VERBS_CMD_CREATE_CQ,
		erdma_ureq_create_cq, erdma_uresp_create_cq);
DECLARE_DRV_CMD(erdma_cmd_create_qp, IB_USER_VERBS_CMD_CREATE_QP,
		erdma_ureq_create_qp, erdma_uresp_create_qp);

#endif
