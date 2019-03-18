/*
 * Copyright (c) 2019 Mellanox Technologies, Inc.  All rights reserved.
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

#define u8 uint8_t

enum mlx5_cap_mode {
	HCA_CAP_OPMOD_GET_CUR	= 1,
};

enum {
	MLX5_CMD_OP_QUERY_HCA_CAP = 0x100,
	MLX5_CMD_OP_CREATE_MKEY = 0x200,
};

struct mlx5_ifc_atomic_caps_bits {
	u8         reserved_at_0[0x40];

	u8         atomic_req_8B_endianness_mode[0x2];
	u8         reserved_at_42[0x4];
	u8         supported_atomic_req_8B_endianness_mode_1[0x1];

	u8         reserved_at_47[0x19];

	u8         reserved_at_60[0x20];

	u8         reserved_at_80[0x10];
	u8         atomic_operations[0x10];

	u8         reserved_at_a0[0x10];
	u8         atomic_size_qp[0x10];

	u8         reserved_at_c0[0x10];
	u8         atomic_size_dc[0x10];

	u8         reserved_at_e0[0x1a0];

	u8         fetch_add_pci_atomic[0x10];
	u8         swap_pci_atomic[0x10];
	u8         compare_swap_pci_atomic[0x10];

	u8         reserved_at_2b0[0x550];
};

union mlx5_ifc_hca_cap_union_bits {
	struct mlx5_ifc_atomic_caps_bits atomic_caps;
	u8         reserved_at_0[0x8000];
};

struct mlx5_ifc_query_hca_cap_out_bits {
	u8         status[0x8];
	u8         reserved_at_8[0x18];

	u8         syndrome[0x20];

	u8         reserved_at_40[0x40];

	union mlx5_ifc_hca_cap_union_bits capability;
};

struct mlx5_ifc_query_hca_cap_in_bits {
	u8         opcode[0x10];
	u8         reserved_at_10[0x10];

	u8         reserved_at_20[0x10];
	u8         op_mod[0x10];

	u8         reserved_at_40[0x40];
};

enum mlx5_cap_type {
	MLX5_CAP_ATOMIC = 3,
};

enum {
	MLX5_MKC_ACCESS_MODE_KLMS  = 0x2,
};

struct mlx5_ifc_mkc_bits {
	u8         reserved_at_0[0x1];
	u8         free[0x1];
	u8         reserved_at_2[0x1];
	u8         access_mode_4_2[0x3];
	u8         reserved_at_6[0x7];
	u8         relaxed_ordering_write[0x1];
	u8         reserved_at_e[0x1];
	u8         small_fence_on_rdma_read_response[0x1];
	u8         umr_en[0x1];
	u8         a[0x1];
	u8         rw[0x1];
	u8         rr[0x1];
	u8         lw[0x1];
	u8         lr[0x1];
	u8         access_mode_1_0[0x2];
	u8         reserved_at_18[0x8];

	u8         qpn[0x18];
	u8         mkey_7_0[0x8];

	u8         reserved_at_40[0x20];

	u8         length64[0x1];
	u8         bsf_en[0x1];
	u8         sync_umr[0x1];
	u8         reserved_at_63[0x2];
	u8         expected_sigerr_count[0x1];
	u8         reserved_at_66[0x1];
	u8         en_rinval[0x1];
	u8         pd[0x18];

	u8         start_addr[0x40];

	u8         len[0x40];

	u8         bsf_octword_size[0x20];

	u8         reserved_at_120[0x80];

	u8         translations_octword_size[0x20];

	u8         reserved_at_1c0[0x1b];
	u8         log_page_size[0x5];

	u8         reserved_at_1e0[0x20];
};

struct mlx5_ifc_create_mkey_out_bits {
	u8         status[0x8];
	u8         reserved_at_8[0x18];

	u8         syndrome[0x20];

	u8         reserved_at_40[0x8];
	u8         mkey_index[0x18];

	u8         reserved_at_60[0x20];
};

struct mlx5_ifc_create_mkey_in_bits {
	u8         opcode[0x10];
	u8         reserved_at_10[0x10];

	u8         reserved_at_20[0x10];
	u8         op_mod[0x10];

	u8         reserved_at_40[0x20];

	u8         pg_access[0x1];
	u8         mkey_umem_valid[0x1];
	u8         reserved_at_62[0x1e];

	struct mlx5_ifc_mkc_bits memory_key_mkey_entry;

	u8         reserved_at_280[0x80];

	u8         translations_octword_actual_size[0x20];

	u8         reserved_at_320[0x560];

	u8         klm_pas_mtt[0][0x20];
};
