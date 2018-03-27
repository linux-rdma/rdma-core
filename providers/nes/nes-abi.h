/*
 * Copyright (c) 2006 - 2010 Intel Corporation.  All rights reserved.
 * Copyright (c) 2006 Open Grid Computing, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * gpl-2.0.txt in the main directory of this source tree, or the
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
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef nes_ABI_H
#define nes_ABI_H

#include <infiniband/kern-abi.h>
#include <rdma/nes-abi.h>
#include <kernel-abi/nes-abi.h>

DECLARE_DRV_CMD(nes_ualloc_pd, IB_USER_VERBS_CMD_ALLOC_PD,
		empty, nes_alloc_pd_resp);
DECLARE_DRV_CMD(nes_ucreate_cq, IB_USER_VERBS_CMD_CREATE_CQ,
		nes_create_cq_req, nes_create_cq_resp);
DECLARE_DRV_CMD(nes_ucreate_qp, IB_USER_VERBS_CMD_CREATE_QP,
		nes_create_qp_req, nes_create_qp_resp);
DECLARE_DRV_CMD(nes_get_context, IB_USER_VERBS_CMD_GET_CONTEXT,
		nes_alloc_ucontext_req, nes_alloc_ucontext_resp);
DECLARE_DRV_CMD(nes_ureg_mr, IB_USER_VERBS_CMD_REG_MR,
		nes_mem_reg_req, empty);

#endif			/* nes_ABI_H */
