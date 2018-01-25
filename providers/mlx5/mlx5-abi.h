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
#include "mlx5dv.h"

#define MLX5_UVERBS_MIN_ABI_VERSION	1
#define MLX5_UVERBS_MAX_ABI_VERSION	1

enum {
	MLX5_QP_FLAG_SIGNATURE		= 1 << 0,
	MLX5_QP_FLAG_SCATTER_CQE	= 1 << 1,
	MLX5_QP_FLAG_TUNNEL_OFFLOADS	= 1 << 2,
	MLX5_QP_FLAG_BFREG_INDEX	= 1 << 3,
	MLX5_QP_FLAG_TYPE_DCT		= 1 << 4,
	MLX5_QP_FLAG_TYPE_DCI		= 1 << 5,
};

enum {
	MLX5_RWQ_FLAG_SIGNATURE		= 1 << 0,
};

enum {
	MLX5_NUM_NON_FP_BFREGS_PER_UAR	= 2,
	NUM_BFREGS_PER_UAR		= 4,
	MLX5_MAX_UARS			= 1 << 8,
	MLX5_MAX_BFREGS			= MLX5_MAX_UARS * MLX5_NUM_NON_FP_BFREGS_PER_UAR,
	MLX5_DEF_TOT_UUARS		= 8 * MLX5_NUM_NON_FP_BFREGS_PER_UAR,
	MLX5_MED_BFREGS_TSHOLD		= 12,
};

enum mlx5_lib_caps {
	MLX5_LIB_CAP_4K_UAR		= 1 << 0,
};

struct mlx5_alloc_ucontext {
	struct ibv_get_context		ibv_req;
	__u32				total_num_uuars;
	__u32				num_low_latency_uuars;
	__u32				flags;
	__u32				comp_mask;
	__u8				cqe_version;
	__u8				reserved0;
	__u16				reserved1;
	__u32				reserved2;
	__u64				lib_caps;
};

enum mlx5_ib_alloc_ucontext_resp_mask {
	MLX5_IB_ALLOC_UCONTEXT_RESP_MASK_CORE_CLOCK_OFFSET = 1UL << 0,
};

/* Bit indexes for the mlx5_alloc_ucontext_resp.clock_info_versions bitmap */
enum {
	MLX5_IB_CLOCK_INFO_V1	= 0,
};

enum {
	MLX5_IB_CLOCK_INFO_KERNEL_UPDATING = 1,
};

struct mlx5_ib_clock_info {
	__u32 sig;
	__u32 resv;
	__u64 nsec;
	__u64 last_cycles;
	__u64 frac;
	__u32 mult;
	__u32 shift;
	__u64 mask;
	__u64 overflow_period;
};

struct mlx5_alloc_ucontext_resp {
	struct ib_uverbs_get_context_resp	ibv_resp;
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
	__u16				reserved1;
	__u32				comp_mask;
	__u32				response_length;
	__u8				cqe_version;
	__u8				cmds_supp_uhw;
	__u8				reserved2;
	__u8				clock_info_versions;
	__u64				hca_core_clock_offset;
	__u32				log_uar_size;
	__u32				num_uars_per_page;
	__u32				num_dyn_bfregs;
	__u32				reserved3;
};

struct mlx5_create_ah_resp {
	struct ib_uverbs_create_ah_resp	ibv_resp;
	__u32				response_length;
	__u8				dmac[ETHERNET_LL_SIZE];
	__u8				reserved[6];
};

struct mlx5_alloc_pd_resp {
	struct ib_uverbs_alloc_pd_resp	ibv_resp;
	__u32				pdn;
};

enum mlx5_create_cq_flags {
	MLX5_CREATE_CQ_FLAGS_CQE_128B_PAD	= 1 << 0,
};

struct mlx5_create_cq {
	struct ibv_create_cq		ibv_cmd;
	__u64				buf_addr;
	__u64				db_addr;
	__u32				cqe_size;
	__u8                            cqe_comp_en;
	__u8                            cqe_comp_res_format;
	__u16                           flags; /* Use enum mlx5_create_cq_flags */
};

struct mlx5_create_cq_resp {
	struct ib_uverbs_create_cq_resp	ibv_resp;
	__u32				cqn;
};

struct mlx5_create_srq {
	struct ibv_create_srq		ibv_cmd;
	__u64				buf_addr;
	__u64				db_addr;
	__u32				flags;
};

struct mlx5_create_srq_resp {
	struct ib_uverbs_create_srq_resp	ibv_resp;
	__u32				srqn;
	__u32				reserved;
};

struct mlx5_create_srq_ex {
	struct ibv_create_xsrq		ibv_cmd;
	__u64				buf_addr;
	__u64				db_addr;
	__u32				flags;
	__u32				reserved;
	__u32                           uidx;
	__u32                           reserved1;
};

struct mlx5_create_qp_drv_ex {
	__u64			buf_addr;
	__u64			db_addr;
	__u32			sq_wqe_count;
	__u32			rq_wqe_count;
	__u32			rq_wqe_shift;
	__u32			flags;
	__u32			uidx;
	__u32			reserved;
	union {
		/* SQ buffer address - used for Raw Packet QP */
		__u64			sq_buf_addr;
		/* DC access key - used to create a DCT QP */
		__u64			access_key;
	};
};

struct mlx5_create_qp_ex {
	struct ibv_create_qp_ex	ibv_cmd;
	struct mlx5_create_qp_drv_ex drv_ex;
};

struct mlx5_create_qp_ex_rss {
	struct ibv_create_qp_ex	ibv_cmd;
	__u64 rx_hash_fields_mask; /* enum ibv_rx_hash_fields */
	__u8 rx_hash_function; /* enum ibv_rx_hash_function_flags */
	__u8 rx_key_len;
	__u8 reserved[6];
	__u8 rx_hash_key[128];
	__u32   comp_mask;
	__u32   create_flags;
};

struct mlx5_create_qp_resp_ex {
	struct ib_uverbs_ex_create_qp_resp	ibv_resp;
	__u32				uuar_index;
	__u32				reserved;
};

struct mlx5_create_qp {
	struct ibv_create_qp		ibv_cmd;
	__u64				buf_addr;
	__u64				db_addr;
	__u32				sq_wqe_count;
	__u32				rq_wqe_count;
	__u32				rq_wqe_shift;
	__u32				flags;
	__u32                           uidx;
	__u32                           bfreg_index;
	union {
		/* SQ buffer address - used for Raw Packet QP */
		__u64			sq_buf_addr;
		/* DC access key - used to create a DCT QP */
		__u64			access_key;
	};
};

struct mlx5_create_qp_resp {
	struct ib_uverbs_create_qp_resp	ibv_resp;
	__u32				uuar_index;
};

enum mlx5_create_wq_comp_mask {
	MLX5_IB_CREATE_WQ_STRIDING_RQ =		1 << 0,
};

struct mlx5_drv_create_wq {
	__u64		buf_addr;
	__u64		db_addr;
	__u32		rq_wqe_count;
	__u32		rq_wqe_shift;
	__u32		user_index;
	__u32		flags;
	__u32		comp_mask;
	__u32		single_stride_log_num_of_bytes;
	__u32		single_wqe_log_num_of_strides;
	__u32		two_byte_shift_en;
};

struct mlx5_create_wq {
	struct ibv_create_wq	ibv_cmd;
	struct mlx5_drv_create_wq	drv;
};

struct mlx5_create_wq_resp {
	struct ib_uverbs_ex_create_wq_resp	ibv_resp;
	__u32			response_length;
	__u32			reserved;
};

struct mlx5_modify_wq {
	struct ibv_modify_wq	ibv_cmd;
	__u32			comp_mask;
	__u32			reserved;
};

struct mlx5_create_rwq_ind_table_resp {
	struct ib_uverbs_ex_create_rwq_ind_table_resp ibv_resp;
};

struct mlx5_destroy_rwq_ind_table {
	struct ibv_destroy_rwq_ind_table ibv_cmd;
};

struct mlx5_resize_cq {
	struct ibv_resize_cq		ibv_cmd;
	__u64				buf_addr;
	__u16				cqe_size;
	__u16				reserved0;
	__u32				reserved1;
};

struct mlx5_resize_cq_resp {
	struct ib_uverbs_resize_cq_resp	ibv_resp;
};

struct mlx5_query_device_ex {
	struct ibv_query_device_ex	ibv_cmd;
};

struct mlx5_reserved_tso_caps {
	__u64 reserved;
};

struct mlx5_rss_caps {
	__u64 rx_hash_fields_mask; /* enum ibv_rx_hash_fields */
	__u8 rx_hash_function; /* enum ibv_rx_hash_function_flags */
	__u8 reserved[7];
};

struct mlx5_packet_pacing_caps {
	struct ibv_packet_pacing_caps caps;
	__u32  reserved;
};

enum mlx5_mpw_caps {
	MLX5_MPW_OBSOLETE	= 1 << 0, /* Obsoleted, don't use */
	MLX5_ALLOW_MPW		= 1 << 1,
	MLX5_SUPPORT_EMPW	= 1 << 2,
};

enum mlx5_query_dev_resp_flags {
	MLX5_QUERY_DEV_RESP_FLAGS_CQE_128B_COMP	= 1 << 0,
	MLX5_QUERY_DEV_RESP_FLAGS_CQE_128B_PAD	= 1 << 1,
};

struct mlx5_striding_rq_caps {
	struct mlx5dv_striding_rq_caps	caps;
	__u32				reserved;
};

struct mlx5_query_device_ex_resp {
	struct ib_uverbs_ex_query_device_resp ibv_resp;
	__u32				comp_mask;
	__u32				response_length;
	struct ibv_tso_caps		tso_caps;
	struct mlx5_rss_caps            rss_caps; /* vendor data channel */
	struct mlx5dv_cqe_comp_caps	cqe_comp_caps;
	struct mlx5_packet_pacing_caps	packet_pacing_caps;
	__u32				support_multi_pkt_send_wqe;
	__u32				flags; /* Use enum mlx5_query_dev_resp_flags */
	struct mlx5dv_sw_parsing_caps	sw_parsing_caps;
	struct mlx5_striding_rq_caps	striding_rq_caps;
	__u32				tunnel_offloads_caps;
	__u32				reserved;
};

struct mlx5_modify_qp_resp_ex {
	struct ib_uverbs_ex_modify_qp_resp base;
	__u32  response_length;
	__u32  dctn;
};

#endif /* MLX5_ABI_H */
