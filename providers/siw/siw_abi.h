/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */

/* Authors: Bernard Metzler <bmt@zurich.ibm.com> */
/* Copyright (c) 2008-2019, IBM Corporation */

#ifndef _SIW_ABI_H
#define _SIW_ABI_H

#include <infiniband/kern-abi.h>
#include <rdma/siw-abi.h>
#include <kernel-abi/siw-abi.h>

DECLARE_DRV_CMD(siw_cmd_alloc_context, IB_USER_VERBS_CMD_GET_CONTEXT,
		empty, siw_uresp_alloc_ctx);
DECLARE_DRV_CMD(siw_cmd_create_cq, IB_USER_VERBS_CMD_CREATE_CQ,
		empty, siw_uresp_create_cq);
DECLARE_DRV_CMD(siw_cmd_create_srq, IB_USER_VERBS_CMD_CREATE_SRQ,
		empty, siw_uresp_create_srq);
DECLARE_DRV_CMD(siw_cmd_create_qp, IB_USER_VERBS_CMD_CREATE_QP,
		empty, siw_uresp_create_qp);
DECLARE_DRV_CMD(siw_cmd_reg_mr, IB_USER_VERBS_CMD_REG_MR,
		siw_ureq_reg_mr, siw_uresp_reg_mr);

#endif /* _SIW_ABI_H */
