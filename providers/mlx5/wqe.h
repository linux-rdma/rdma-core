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

#ifndef WQE_H
#define WQE_H

#include <stdint.h>

#include "mlx5dv.h"

struct mlx5_sg_copy_ptr {
	int	index;
	int	offset;
};

struct mlx5_eqe_comp {
	uint32_t	reserved[6];
	uint32_t	cqn;
};

struct mlx5_eqe_qp_srq {
	uint32_t	reserved[6];
	uint32_t	qp_srq_n;
};

struct mlx5_wqe_eth_pad {
	uint8_t rsvd0[16];
};

struct mlx5_wqe_xrc_seg {
	__be32		xrc_srqn;
	uint8_t		rsvd[12];
};

struct mlx5_wqe_masked_atomic_seg {
	uint64_t	swap_add;
	uint64_t	compare;
	uint64_t	swap_add_mask;
	uint64_t	compare_mask;
};

enum {
	MLX5_IPOIB_INLINE_MIN_HEADER_SIZE	= 4,
	MLX5_SOURCE_QPN_INLINE_MAX_HEADER_SIZE	= 18,
	MLX5_ETH_L2_INLINE_HEADER_SIZE	= 18,
	MLX5_ETH_L2_MIN_HEADER_SIZE	= 14,
};

struct mlx5_seg_set_psv {
	uint8_t		rsvd[4];
	uint16_t	syndrome;
	uint16_t	status;
	uint16_t	block_guard;
	uint16_t	app_tag;
	uint32_t	ref_tag;
	uint32_t	mkey;
	uint64_t	va;
};

struct mlx5_seg_get_psv {
	uint8_t		rsvd[19];
	uint8_t		num_psv;
	uint32_t	l_key;
	uint64_t	va;
	uint32_t	psv_index[4];
};

struct mlx5_seg_check_psv {
	uint8_t		rsvd0[2];
	uint16_t	err_coalescing_op;
	uint8_t		rsvd1[2];
	uint16_t	xport_err_op;
	uint8_t		rsvd2[2];
	uint16_t	xport_err_mask;
	uint8_t		rsvd3[7];
	uint8_t		num_psv;
	uint32_t	l_key;
	uint64_t	va;
	uint32_t	psv_index[4];
};

struct mlx5_rwqe_sig {
	uint8_t		rsvd0[4];
	uint8_t		signature;
	uint8_t		rsvd1[11];
};

struct mlx5_wqe_signature_seg {
	uint8_t		rsvd0[4];
	uint8_t		signature;
	uint8_t		rsvd1[11];
};

struct mlx5_wqe_inline_seg {
	__be32		byte_count;
};

enum {
	MLX5_WQE_MKEY_CONTEXT_FLAGS_BSF_ENABLE = 1 << 30,
	MLX5_WQE_MKEY_CONTEXT_SIG_ERR_CNT_MASK = 1,
	MLX5_WQE_MKEY_CONTEXT_SIG_ERR_CNT_SHIFT = 26,
};

enum {
	MLX5_BSF_SIZE_BASIC = 0,
	MLX5_BSF_SIZE_EXTENDED = 1,
	MLX5_BSF_SIZE_WITH_INLINE = 2,
	MLX5_BSF_SIZE_SIG_AND_CRYPTO = 3,
	MLX5_BSF_TYPE_CRYPTO = 1,
	MLX5_BSF_SIZE_SHIFT = 6,
	MLX5_BSF_SBS_SHIFT = 4,

	/* Block Format Selector */
	MLX5_BFS_CRC32_BASE = 0x20,
	MLX5_BFS_CRC32C_BASE = 0x40,
	MLX5_BFS_CRC64_XP10_BASE = 0x50,
	MLX5_BFS_CRC_REPEAT_BIT = 0x2,
	MLX5_BFS_CRC_BLOCK_SIGS_COV_BIT = 0x2,
	MLX5_BFS_CRC_SEED_BIT = 0x1,
	MLX5_BFS_SHIFT = 24,

	MLX5_BSF_PSV_INDEX_MASK = 0xFFFFFF,
	/* Inline section */
	MLX5_BSF_INL_VALID = 1 << 15,
	MLX5_BSF_REFRESH_DIF = 1 << 14,
	MLX5_BSF_REPEAT_BLOCK = 1 << 7,
	MLX5_BSF_INC_REFTAG = 1 << 6,
	MLX5_BSF_SEED = 1 << 3,
	MLX5_BSF_APPTAG_ESCAPE = 0x1,
	MLX5_BSF_APPREF_ESCAPE = 0x2,
	MLX5_T10DIF_CRC = 0x1,
	MLX5_T10DIF_IPCS = 0x2,
};

struct mlx5_bsf_inl {
	__be16 vld_refresh;
	__be16 dif_apptag;
	__be32 dif_reftag;
	uint8_t sig_type;
	uint8_t rp_inv_seed;
	uint8_t rsvd[3];
	uint8_t dif_inc_ref_guard_check;
	__be16 dif_app_bitmask_check;
};

struct mlx5_crypto_bsf {
	uint8_t bsf_size_type;
	uint8_t enc_order;
	uint8_t rsvd0;
	uint8_t enc_standard;
	__be32 raw_data_size;
	uint8_t bs_pointer;
	uint8_t rsvd1[7];
	__be32 xts_init_tweak[4];
	__be32 rsvd_dek_ptr;
	uint8_t rsvd2[4];
	uint8_t keytag[8];
	uint8_t rsvd3[16];
};

struct mlx5_bsf {
	struct mlx5_bsf_basic {
		uint8_t bsf_size_sbs;
		uint8_t check_byte_mask;
		union {
			uint8_t copy_byte_mask;
			uint8_t bs_selector;
			uint8_t rsvd_wflags;
		} wire;
		union {
			uint8_t bs_selector;
			uint8_t rsvd_mflags;
		} mem;
		__be32 raw_data_size;
		__be32 w_bfs_psv;
		__be32 m_bfs_psv;
	} basic;
	struct mlx5_bsf_ext {
		__be32 t_init_gen_pro_size;
		__be32 rsvd_epi_size;
		__be32 w_tfs_psv;
		__be32 m_tfs_psv;
	} ext;
	struct mlx5_bsf_inl w_inl;
	struct mlx5_bsf_inl m_inl;
};

struct mlx5_wqe_set_psv_seg {
	__be32 psv_index;
	__be16 syndrome;
	uint8_t reserved[2];
	__be64 transient_signature;
};

enum {
	MLX5_OPC_MOD_MMO_DMA = 0x1,
};

struct mlx5_mmo_metadata_seg {
	__be32 mmo_control_31_0;
	__be32 local_key;
	__be64 local_address;
};

struct mlx5_mmo_wqe {
	struct mlx5_wqe_ctrl_seg ctrl;
	struct mlx5_mmo_metadata_seg mmo_meta;
	struct mlx5_wqe_data_seg src;
	struct mlx5_wqe_data_seg dest;
};

#endif /* WQE_H */
