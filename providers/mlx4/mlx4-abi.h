/*
 * Copyright (c) 2007 Cisco, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
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
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef MLX4_ABI_H
#define MLX4_ABI_H

#include <infiniband/kern-abi.h>
#include <rdma/mlx4-abi.h>
#include <kernel-abi/mlx4-abi.h>

#define MLX4_UVERBS_MIN_ABI_VERSION	2
#define MLX4_UVERBS_MAX_ABI_VERSION	4

#define MLX4_UVERBS_NO_DEV_CAPS_ABI_VERSION	3

DECLARE_DRV_CMD(mlx4_alloc_pd, IB_USER_VERBS_CMD_ALLOC_PD,
		empty, mlx4_ib_alloc_pd_resp);
DECLARE_DRV_CMD(mlx4_create_cq, IB_USER_VERBS_CMD_CREATE_CQ,
		mlx4_ib_create_cq, mlx4_ib_create_cq_resp);
DECLARE_DRV_CMD(mlx4_create_cq_ex, IB_USER_VERBS_EX_CMD_CREATE_CQ,
		mlx4_ib_create_cq, mlx4_ib_create_cq_resp);
DECLARE_DRV_CMD(mlx4_create_qp, IB_USER_VERBS_CMD_CREATE_QP,
		mlx4_ib_create_qp, empty);
DECLARE_DRV_CMD(mlx4_create_qp_ex, IB_USER_VERBS_EX_CMD_CREATE_QP,
		mlx4_ib_create_qp, empty);
DECLARE_DRV_CMD(mlx4_create_qp_ex_rss, IB_USER_VERBS_EX_CMD_CREATE_QP,
		mlx4_ib_create_qp_rss, empty);
DECLARE_DRV_CMD(mlx4_create_srq, IB_USER_VERBS_CMD_CREATE_SRQ,
		mlx4_ib_create_srq, mlx4_ib_create_srq_resp);
DECLARE_DRV_CMD(mlx4_create_wq, IB_USER_VERBS_EX_CMD_CREATE_WQ,
		mlx4_ib_create_wq, empty);
DECLARE_DRV_CMD(mlx4_create_xsrq, IB_USER_VERBS_CMD_CREATE_XSRQ,
		mlx4_ib_create_srq, mlx4_ib_create_srq_resp);
DECLARE_DRV_CMD(mlx4_alloc_ucontext_v3, IB_USER_VERBS_CMD_GET_CONTEXT,
		empty, mlx4_ib_alloc_ucontext_resp_v3);
DECLARE_DRV_CMD(mlx4_alloc_ucontext, IB_USER_VERBS_CMD_GET_CONTEXT,
		empty, mlx4_ib_alloc_ucontext_resp);
DECLARE_DRV_CMD(mlx4_modify_wq, IB_USER_VERBS_EX_CMD_MODIFY_WQ,
		mlx4_ib_modify_wq, empty);
DECLARE_DRV_CMD(mlx4_query_device_ex, IB_USER_VERBS_EX_CMD_QUERY_DEVICE,
		empty, mlx4_uverbs_ex_query_device_resp);
DECLARE_DRV_CMD(mlx4_resize_cq, IB_USER_VERBS_CMD_RESIZE_CQ,
		mlx4_ib_resize_cq, empty);

#endif /* MLX4_ABI_H */
