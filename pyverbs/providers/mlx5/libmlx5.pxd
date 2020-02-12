# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

include 'mlx5dv_enums.pxd'

from libc.stdint cimport uint32_t, uint64_t
from libcpp cimport bool

cimport pyverbs.libibverbs as v


cdef extern from 'infiniband/mlx5dv.h':

    cdef struct mlx5dv_context_attr:
        unsigned int    flags
        unsigned long   comp_mask

    cdef struct mlx5dv_cqe_comp_caps:
        unsigned int    max_num
        unsigned int    supported_format

    cdef struct mlx5dv_sw_parsing_caps:
        unsigned int    sw_parsing_offloads
        unsigned int    supported_qpts

    cdef struct mlx5dv_striding_rq_caps:
        unsigned int    min_single_stride_log_num_of_bytes
        unsigned int    max_single_stride_log_num_of_bytes
        unsigned int    min_single_wqe_log_num_of_strides
        unsigned int    max_single_wqe_log_num_of_strides
        unsigned int    supported_qpts

    cdef struct mlx5dv_context:
        unsigned char           version
        unsigned long           flags
        unsigned long           comp_mask
        mlx5dv_cqe_comp_caps    cqe_comp_caps
        mlx5dv_sw_parsing_caps  sw_parsing_caps
        mlx5dv_striding_rq_caps striding_rq_caps
        unsigned int            tunnel_offloads_caps
        unsigned int            max_dynamic_bfregs
        unsigned long           max_clock_info_update_nsec
        unsigned int            flow_action_flags
        unsigned int            dc_odp_caps

    cdef struct mlx5dv_dc_init_attr:
        mlx5dv_dc_type      dc_type
        unsigned long       dct_access_key

    cdef struct mlx5dv_qp_init_attr:
        unsigned long       comp_mask
        unsigned int        create_flags
        mlx5dv_dc_init_attr dc_init_attr
        unsigned long       send_ops_flags

    cdef struct mlx5dv_cq_init_attr:
        unsigned long   comp_mask
        unsigned char   cqe_comp_res_format
        unsigned int    flags
        unsigned short  cqe_size

    cdef struct mlx5dv_var:
        uint32_t    page_id
        uint32_t    length
        long        mmap_off
        uint64_t    comp_mask

    bool mlx5dv_is_supported(v.ibv_device *device)
    v.ibv_context* mlx5dv_open_device(v.ibv_device *device,
                                      mlx5dv_context_attr *attr)
    int mlx5dv_query_device(v.ibv_context *ctx, mlx5dv_context *attrs_out)

    v.ibv_qp *mlx5dv_create_qp(v.ibv_context *context,
                               v.ibv_qp_init_attr_ex *qp_attr,
                               mlx5dv_qp_init_attr *mlx5_qp_attr)
    v.ibv_cq_ex *mlx5dv_create_cq(v.ibv_context *context,
                                  v.ibv_cq_init_attr_ex *cq_attr,
                                  mlx5dv_cq_init_attr *mlx5_cq_attr)

    mlx5dv_var *mlx5dv_alloc_var(v.ibv_context *context, uint32_t flags)
    void mlx5dv_free_var(mlx5dv_var *dv_var)
