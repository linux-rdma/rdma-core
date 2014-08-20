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

#define MLX5_UVERBS_MIN_ABI_VERSION	1
#define MLX5_UVERBS_MAX_ABI_VERSION	1

enum {
	MLX5_QP_FLAG_SIGNATURE		= 1 << 0,
	MLX5_QP_FLAG_SCATTER_CQE	= 1 << 1,
};

enum {
	MLX5_NUM_UUARS_PER_PAGE = 2,
	MLX5_MAX_UAR_PAGES	= 1 << 8,
	MLX5_MAX_UUARS		= MLX5_MAX_UAR_PAGES * MLX5_NUM_UUARS_PER_PAGE,
	MLX5_DEF_TOT_UUARS	= 8 * MLX5_NUM_UUARS_PER_PAGE,
};

struct mlx5_alloc_ucontext {
	struct ibv_get_context		ibv_req;
	__u32				total_num_uuars;
	__u32				num_low_latency_uuars;
	__u32				flags;
	__u32				reserved;
};

struct mlx5_alloc_ucontext_resp {
	struct ibv_get_context_resp	ibv_resp;
	__u32				qp_tab_size;
	__u32				bf_reg_size;
	__u32				tot_uuars;
	__u32				cache_line_size;
	__u16				max_sq_desc_sz;
	__u16				max_rq_desc_sz;
	__u32				max_send_wqebb;
	__u32				max_recv_wr;
	__u32				max_srq_recv_wr;
	__u16				num_ports;
	__u16				reserved;
};

struct mlx5_alloc_pd_resp {
	struct ibv_alloc_pd_resp	ibv_resp;
	__u32				pdn;
};

struct mlx5_create_cq {
	struct ibv_create_cq		ibv_cmd;
	__u64				buf_addr;
	__u64				db_addr;
	__u32				cqe_size;
};

struct mlx5_create_cq_resp {
	struct ibv_create_cq_resp	ibv_resp;
	__u32				cqn;
};

struct mlx5_create_srq {
	struct ibv_create_srq		ibv_cmd;
	__u64				buf_addr;
	__u64				db_addr;
	__u32				flags;
};

struct mlx5_create_srq_resp {
	struct ibv_create_srq_resp	ibv_resp;
	__u32				srqn;
	__u32				reserved;
};

struct mlx5_create_srq_ex {
	struct ibv_create_xsrq		ibv_cmd;
	__u64				buf_addr;
	__u64				db_addr;
	__u32				flags;
};

struct mlx5_create_qp {
	struct ibv_create_qp		ibv_cmd;
	__u64				buf_addr;
	__u64				db_addr;
	__u32				sq_wqe_count;
	__u32				rq_wqe_count;
	__u32				rq_wqe_shift;
	__u32				flags;
};

struct mlx5_create_qp_resp {
	struct ibv_create_qp_resp	ibv_resp;
	__u32				uuar_index;
};

struct mlx5_resize_cq {
	struct ibv_resize_cq		ibv_cmd;
	__u64				buf_addr;
	__u16				cqe_size;
	__u16				reserved0;
	__u32				reserved1;
};

struct mlx5_resize_cq_resp {
	struct ibv_resize_cq_resp	ibv_resp;
};

#endif /* MLX4_ABI_H */
