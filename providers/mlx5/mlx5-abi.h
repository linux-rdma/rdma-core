/*
 * Copyright (c) 2012 Mellanox Technologies, Inc.  All rights reserved.
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

#ifndef MLX5_ABI_H
#define MLX5_ABI_H

#include <infiniband/kern-abi.h>
#include <infiniband/verbs.h>
#include <rdma/mlx5-abi.h>
#include <kernel-abi/mlx5-abi.h>
#include "mlx5dv.h"

#define MLX5_UVERBS_MIN_ABI_VERSION	1
#define MLX5_UVERBS_MAX_ABI_VERSION	1

enum {
	MLX5_NUM_NON_FP_BFREGS_PER_UAR	= 2,
	NUM_BFREGS_PER_UAR		= 4,
	MLX5_MAX_UARS			= 1 << 8,
	MLX5_MAX_BFREGS			= MLX5_MAX_UARS * MLX5_NUM_NON_FP_BFREGS_PER_UAR,
	MLX5_DEF_TOT_UUARS		= 8 * MLX5_NUM_NON_FP_BFREGS_PER_UAR,
	MLX5_MED_BFREGS_TSHOLD		= 12,
};

DECLARE_DRV_CMD(mlx5_alloc_ucontext, IB_USER_VERBS_CMD_GET_CONTEXT,
		mlx5_ib_alloc_ucontext_req_v2, mlx5_ib_alloc_ucontext_resp);
DECLARE_DRV_CMD(mlx5_create_ah, IB_USER_VERBS_CMD_CREATE_AH,
		empty, mlx5_ib_create_ah_resp);
DECLARE_DRV_CMD(mlx5_alloc_pd, IB_USER_VERBS_CMD_ALLOC_PD,
		empty, mlx5_ib_alloc_pd_resp);
DECLARE_DRV_CMD(mlx5_create_cq, IB_USER_VERBS_CMD_CREATE_CQ,
		mlx5_ib_create_cq, mlx5_ib_create_cq_resp);
DECLARE_DRV_CMD(mlx5_create_cq_ex, IB_USER_VERBS_EX_CMD_CREATE_CQ,
		mlx5_ib_create_cq, mlx5_ib_create_cq_resp);
DECLARE_DRV_CMD(mlx5_create_srq, IB_USER_VERBS_CMD_CREATE_SRQ,
		mlx5_ib_create_srq, mlx5_ib_create_srq_resp);
DECLARE_DRV_CMD(mlx5_create_srq_ex, IB_USER_VERBS_CMD_CREATE_XSRQ,
		mlx5_ib_create_srq, mlx5_ib_create_srq_resp);
DECLARE_DRV_CMD(mlx5_create_qp_ex, IB_USER_VERBS_EX_CMD_CREATE_QP,
		mlx5_ib_create_qp, mlx5_ib_create_qp_resp);
DECLARE_DRV_CMD(mlx5_create_qp_ex_rss, IB_USER_VERBS_EX_CMD_CREATE_QP,
		mlx5_ib_create_qp_rss, mlx5_ib_create_qp_resp);
DECLARE_DRV_CMD(mlx5_create_qp, IB_USER_VERBS_CMD_CREATE_QP,
		mlx5_ib_create_qp, mlx5_ib_create_qp_resp);
DECLARE_DRV_CMD(mlx5_create_wq, IB_USER_VERBS_EX_CMD_CREATE_WQ,
		mlx5_ib_create_wq, mlx5_ib_create_wq_resp);
DECLARE_DRV_CMD(mlx5_modify_wq, IB_USER_VERBS_EX_CMD_MODIFY_WQ,
		mlx5_ib_modify_wq, empty);
DECLARE_DRV_CMD(mlx5_create_rwq_ind_table, IB_USER_VERBS_EX_CMD_CREATE_RWQ_IND_TBL,
		empty, empty);
DECLARE_DRV_CMD(mlx5_destroy_rwq_ind_table, IB_USER_VERBS_EX_CMD_DESTROY_RWQ_IND_TBL,
		empty, empty);
DECLARE_DRV_CMD(mlx5_resize_cq, IB_USER_VERBS_CMD_RESIZE_CQ,
		mlx5_ib_resize_cq, empty);
DECLARE_DRV_CMD(mlx5_query_device_ex, IB_USER_VERBS_EX_CMD_QUERY_DEVICE,
		empty, mlx5_ib_query_device_resp);
DECLARE_DRV_CMD(mlx5_modify_qp_ex, IB_USER_VERBS_EX_CMD_MODIFY_QP,
		empty, mlx5_ib_modify_qp_resp);

struct mlx5_modify_qp {
	struct ibv_modify_qp_ex		ibv_cmd;
	__u32				comp_mask;
	struct mlx5_ib_burst_info	burst_info;
	__u32				reserved;
};

#endif /* MLX5_ABI_H */
