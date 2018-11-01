/*******************************************************************************
*
* Copyright (c) 2015-2016 Intel Corporation.  All rights reserved.
*
* This software is available to you under a choice of one of two
* licenses.  You may choose to be licensed under the terms of the GNU
* General Public License (GPL) Version 2, available from the file
* COPYING in the main directory of this source tree, or the
* OpenFabrics.org BSD license below:
*
*   Redistribution and use in source and binary forms, with or
*   without modification, are permitted provided that the following
*   conditions are met:
*
*    - Redistributions of source code must retain the above
*	copyright notice, this list of conditions and the following
*	disclaimer.
*
*    - Redistributions in binary form must reproduce the above
*	copyright notice, this list of conditions and the following
*	disclaimer in the documentation and/or other materials
*	provided with the distribution.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
* BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
* ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
* CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*
*******************************************************************************/

#ifndef PROVIDER_I40IW_ABI_H
#define PROVIDER_I40IW_ABI_H

#include <infiniband/kern-abi.h>
#include <rdma/i40iw-abi.h>
#include <kernel-abi/i40iw-abi.h>

#define I40IW_ABI_VER 5

DECLARE_DRV_CMD(i40iw_ualloc_pd, IB_USER_VERBS_CMD_ALLOC_PD,
		empty, i40iw_alloc_pd_resp);
DECLARE_DRV_CMD(i40iw_ucreate_cq, IB_USER_VERBS_CMD_CREATE_CQ,
		i40iw_create_cq_req, i40iw_create_cq_resp);
DECLARE_DRV_CMD(i40iw_ucreate_qp, IB_USER_VERBS_CMD_CREATE_QP,
		i40iw_create_qp_req, i40iw_create_qp_resp);
DECLARE_DRV_CMD(i40iw_get_context, IB_USER_VERBS_CMD_GET_CONTEXT,
		i40iw_alloc_ucontext_req, i40iw_alloc_ucontext_resp);
DECLARE_DRV_CMD(i40iw_ureg_mr, IB_USER_VERBS_CMD_REG_MR,
		i40iw_mem_reg_req, empty);

#endif /* I40IW_ABI_H */
