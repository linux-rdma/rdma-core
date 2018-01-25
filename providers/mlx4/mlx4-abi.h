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

#define MLX4_UVERBS_MIN_ABI_VERSION	2
#define MLX4_UVERBS_MAX_ABI_VERSION	4

#define MLX4_UVERBS_NO_DEV_CAPS_ABI_VERSION	3

enum {
	MLX4_USER_DEV_CAP_64B_CQE	= 1L << 0
};

struct mlx4_alloc_ucontext_resp_v3 {
	struct ib_uverbs_get_context_resp	ibv_resp;
	__u32				qp_tab_size;
	__u16				bf_reg_size;
	__u16				bf_regs_per_page;
};

enum mlx4_query_dev_ex_resp_mask {
	MLX4_QUERY_DEV_RESP_MASK_CORE_CLOCK_OFFSET = 1UL << 0,
};

struct mlx4_alloc_ucontext_resp {
	struct ib_uverbs_get_context_resp	ibv_resp;
	__u32				dev_caps;
	__u32				qp_tab_size;
	__u16				bf_reg_size;
	__u16				bf_regs_per_page;
	__u32				cqe_size;
};

struct mlx4_alloc_pd_resp {
	struct ib_uverbs_alloc_pd_resp	ibv_resp;
	__u32				pdn;
	__u32				reserved;
};

struct mlx4_create_cq {
	struct ibv_create_cq		ibv_cmd;
	__u64				buf_addr;
	__u64				db_addr;
};

struct mlx4_create_cq_resp {
	struct ib_uverbs_create_cq_resp	ibv_resp;
	__u32				cqn;
	__u32				reserved;
};

struct mlx4_create_cq_ex {
	struct ibv_create_cq_ex		ibv_cmd;
	__u64				buf_addr;
	__u64				db_addr;
};

struct mlx4_create_cq_resp_ex {
	struct ib_uverbs_ex_create_cq_resp	ibv_resp;
	__u32				cqn;
	__u32				reserved;
};

struct mlx4_resize_cq {
	struct ibv_resize_cq		ibv_cmd;
	__u64				buf_addr;
};

struct mlx4_rss_caps {
	__u64 rx_hash_fields_mask; /* enum ibv_rx_hash_fields */
	__u8 rx_hash_function; /* enum ibv_rx_hash_function_flags */
	__u8 reserved[7];
};

struct mlx4_query_device_ex_resp {
	struct ib_uverbs_ex_query_device_resp ibv_resp;
	__u32				comp_mask;
	__u32				response_length;
	__u64				hca_core_clock_offset;
	__u32				max_inl_recv_sz;
	struct mlx4_rss_caps            rss_caps; /* vendor data channel */
};

struct mlx4_query_device_ex {
	struct ibv_query_device_ex	ibv_cmd;
};

struct mlx4_create_srq {
	struct ibv_create_srq		ibv_cmd;
	__u64				buf_addr;
	__u64				db_addr;
};

struct mlx4_create_xsrq {
	struct ibv_create_xsrq		ibv_cmd;
	__u64				buf_addr;
	__u64				db_addr;
};

struct mlx4_create_srq_resp {
	struct ib_uverbs_create_srq_resp	ibv_resp;
	__u32				srqn;
	__u32				reserved;
};

struct mlx4_create_qp {
	struct ibv_create_qp		ibv_cmd;
	__u64				buf_addr;
	__u64				db_addr;
	__u8				log_sq_bb_count;
	__u8				log_sq_stride;
	__u8				sq_no_prefetch;	/* was reserved in ABI 2 */
	__u8				reserved;
	__u32				inl_recv_sz;
};

struct mlx4_create_qp_drv_ex_rss {
	__u64		hash_fields_mask; /* enum ibv_rx_hash_fields */
	__u8		hash_function; /* enum ibv_rx_hash_function_flags */
	__u8		reserved[7];
	__u8		hash_key[40];
	__u32		comp_mask;
	__u32		reserved1;
};

struct mlx4_create_qp_ex_rss {
	struct ibv_create_qp_ex		 ibv_cmd;
	struct mlx4_create_qp_drv_ex_rss drv_ex;
};

struct mlx4_create_qp_drv_ex {
	__u64		buf_addr;
	__u64		db_addr;
	__u8		log_sq_bb_count;
	__u8		log_sq_stride;
	__u8		sq_no_prefetch;	/* was reserved in ABI 2 */
	__u8		reserved[5];
};

struct mlx4_create_qp_ex {
	struct ibv_create_qp_ex		ibv_cmd;
	struct mlx4_create_qp_drv_ex	drv_ex;
};

struct mlx4_create_qp_resp_ex {
	struct ib_uverbs_ex_create_qp_resp	ibv_resp;
};

struct mlx4_drv_create_wq {
	__u64		buf_addr;
	__u64		db_addr;
	__u8		log_range_size;
	__u8		reserved[3];
	__u32		comp_mask;
};

struct mlx4_create_wq {
	struct ibv_create_wq		ibv_cmd;
	struct mlx4_drv_create_wq	drv;
};

struct mlx4_modify_wq {
	struct ibv_modify_wq	ibv_cmd;
	__u32			comp_mask;
	__u32			reserved;
};

#endif /* MLX4_ABI_H */
