/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR Linux-OpenIB) */
/*
 * Copyright (c) 2024 ZTE Corporation.
 *
 * This software is available to you under a choice of one of two
 * licenses. You may choose to be licensed under the terms of the GNU
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
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef __ZXDH_ABI_H__
#define __ZXDH_ABI_H__

#include <infiniband/kern-abi.h>
#include <rdma/zxdh-abi.h>
#include <kernel-abi/zxdh-abi.h>
#include "zxdh_verbs.h"

#define ZXDH_MIN_ABI_VERSION 0
#define ZXDH_MAX_ABI_VERSION 5

DECLARE_DRV_CMD(zxdh_ualloc_pd, IB_USER_VERBS_CMD_ALLOC_PD, empty,
		zxdh_alloc_pd_resp);
DECLARE_DRV_CMD(zxdh_ucreate_cq, IB_USER_VERBS_CMD_CREATE_CQ,
		zxdh_create_cq_req, zxdh_create_cq_resp);
DECLARE_DRV_CMD(zxdh_ucreate_cq_ex, IB_USER_VERBS_EX_CMD_CREATE_CQ,
		zxdh_create_cq_req, zxdh_create_cq_resp);
DECLARE_DRV_CMD(zxdh_uresize_cq, IB_USER_VERBS_CMD_RESIZE_CQ,
		zxdh_resize_cq_req, empty);
DECLARE_DRV_CMD(zxdh_ucreate_qp, IB_USER_VERBS_CMD_CREATE_QP,
		zxdh_create_qp_req, zxdh_create_qp_resp);
DECLARE_DRV_CMD(zxdh_umodify_qp, IB_USER_VERBS_EX_CMD_MODIFY_QP,
		zxdh_modify_qp_req, zxdh_modify_qp_resp);
DECLARE_DRV_CMD(zxdh_get_context, IB_USER_VERBS_CMD_GET_CONTEXT,
		zxdh_alloc_ucontext_req, zxdh_alloc_ucontext_resp);
DECLARE_DRV_CMD(zxdh_ureg_mr, IB_USER_VERBS_CMD_REG_MR, zxdh_mem_reg_req,
		zxdh_reg_mr_resp);
DECLARE_DRV_CMD(zxdh_urereg_mr, IB_USER_VERBS_CMD_REREG_MR, zxdh_mem_reg_req,
		empty);
DECLARE_DRV_CMD(zxdh_ucreate_ah, IB_USER_VERBS_CMD_CREATE_AH, empty,
		zxdh_create_ah_resp);
DECLARE_DRV_CMD(zxdh_ucreate_srq, IB_USER_VERBS_CMD_CREATE_SRQ,
		zxdh_create_srq_req, zxdh_create_srq_resp);
#endif /* __ZXDH_ABI_H__ */
