# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

#cython: language_level=3

cdef extern from 'infiniband/mlx5dv.h':

    cpdef enum mlx5dv_context_comp_mask:
        MLX5DV_CONTEXT_MASK_CQE_COMPRESION      = 1 << 0
        MLX5DV_CONTEXT_MASK_SWP                 = 1 << 1
        MLX5DV_CONTEXT_MASK_STRIDING_RQ         = 1 << 2
        MLX5DV_CONTEXT_MASK_TUNNEL_OFFLOADS     = 1 << 3
        MLX5DV_CONTEXT_MASK_DYN_BFREGS          = 1 << 4
        MLX5DV_CONTEXT_MASK_CLOCK_INFO_UPDATE   = 1 << 5
        MLX5DV_CONTEXT_MASK_FLOW_ACTION_FLAGS   = 1 << 6

    cpdef enum mlx5dv_context_flags:
        MLX5DV_CONTEXT_FLAGS_CQE_V1                     = 1 << 0
        MLX5DV_CONTEXT_FLAGS_MPW_ALLOWED                = 1 << 2
        MLX5DV_CONTEXT_FLAGS_ENHANCED_MPW               = 1 << 3
        MLX5DV_CONTEXT_FLAGS_CQE_128B_COMP              = 1 << 4
        MLX5DV_CONTEXT_FLAGS_CQE_128B_PAD               = 1 << 5
        MLX5DV_CONTEXT_FLAGS_PACKET_BASED_CREDIT_MODE   = 1 << 6

    cpdef enum mlx5dv_sw_parsing_offloads:
        MLX5DV_SW_PARSING       = 1 << 0
        MLX5DV_SW_PARSING_CSUM  = 1 << 1
        MLX5DV_SW_PARSING_LSO   = 1 << 2

    cpdef enum mlx5dv_cqe_comp_res_format:
        MLX5DV_CQE_RES_FORMAT_HASH          = 1 << 0
        MLX5DV_CQE_RES_FORMAT_CSUM          = 1 << 1
        MLX5DV_CQE_RES_FORMAT_CSUM_STRIDX   = 1 << 2

    cpdef enum mlx5dv_tunnel_offloads:
        MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_VXLAN            = 1 << 0
        MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_GRE              = 1 << 1
        MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_GENEVE           = 1 << 2
        MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_CW_MPLS_OVER_GRE = 1 << 3
        MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_CW_MPLS_OVER_UDP = 1 << 4

    cpdef enum mlx5dv_flow_action_cap_flags:
        MLX5DV_FLOW_ACTION_FLAGS_ESP_AES_GCM                = 1 << 0
        MLX5DV_FLOW_ACTION_FLAGS_ESP_AES_GCM_REQ_METADATA   = 1 << 1
        MLX5DV_FLOW_ACTION_FLAGS_ESP_AES_GCM_SPI_STEERING   = 1 << 2
        MLX5DV_FLOW_ACTION_FLAGS_ESP_AES_GCM_FULL_OFFLOAD   = 1 << 3
        MLX5DV_FLOW_ACTION_FLAGS_ESP_AES_GCM_TX_IV_IS_ESN   = 1 << 4
