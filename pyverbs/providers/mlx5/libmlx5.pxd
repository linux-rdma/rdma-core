# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

include 'mlx5dv_enums.pxd'

from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t
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
        uint8_t                 num_lag_ports

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

    cdef struct mlx5dv_pp:
        uint16_t index

    cdef struct mlx5dv_devx_uar:
        void        *reg_addr;
        void        *base_addr;
        uint32_t    page_id;
        long        mmap_off;
        uint64_t    comp_mask;

    cdef struct mlx5dv_qp_ex:
        uint64_t comp_mask

    cdef struct mlx5dv_sched_node

    cdef struct mlx5dv_sched_leaf

    cdef struct mlx5dv_sched_attr:
        mlx5dv_sched_node *parent;
        uint32_t flags;
        uint32_t bw_share;
        uint32_t max_avg_bw;
        uint64_t comp_mask;

    bool mlx5dv_is_supported(v.ibv_device *device)
    v.ibv_context* mlx5dv_open_device(v.ibv_device *device,
                                      mlx5dv_context_attr *attr)
    int mlx5dv_query_device(v.ibv_context *ctx, mlx5dv_context *attrs_out)

    v.ibv_qp *mlx5dv_create_qp(v.ibv_context *context,
                               v.ibv_qp_init_attr_ex *qp_attr,
                               mlx5dv_qp_init_attr *mlx5_qp_attr)
    int mlx5dv_query_qp_lag_port(v.ibv_qp *qp, uint8_t *port_num,
                                 uint8_t *active_port_num)
    int mlx5dv_modify_qp_lag_port(v.ibv_qp *qp, uint8_t port_num)
    int mlx5dv_modify_qp_udp_sport(v.ibv_qp *qp, uint16_t udp_sport)
    v.ibv_cq_ex *mlx5dv_create_cq(v.ibv_context *context,
                                  v.ibv_cq_init_attr_ex *cq_attr,
                                  mlx5dv_cq_init_attr *mlx5_cq_attr)

    mlx5dv_var *mlx5dv_alloc_var(v.ibv_context *context, uint32_t flags)
    void mlx5dv_free_var(mlx5dv_var *dv_var)
    mlx5dv_pp *mlx5dv_pp_alloc(v.ibv_context *context, size_t pp_context_sz,
                               const void *pp_context, uint32_t flags)
    void mlx5dv_pp_free(mlx5dv_pp *pp)
    void mlx5dv_wr_set_dc_addr(mlx5dv_qp_ex *mqp, v.ibv_ah *ah,
                               uint32_t remote_dctn, uint64_t remote_dc_key)
    mlx5dv_qp_ex *mlx5dv_qp_ex_from_ibv_qp_ex(v.ibv_qp_ex *qp_ex)
    mlx5dv_sched_node *mlx5dv_sched_node_create(v.ibv_context *context,
                                                mlx5dv_sched_attr *sched_attr)
    mlx5dv_sched_leaf *mlx5dv_sched_leaf_create(v.ibv_context *context,
                                                mlx5dv_sched_attr *sched_attr)
    int mlx5dv_sched_node_modify(mlx5dv_sched_node *node,
                                 mlx5dv_sched_attr *sched_attr)
    int mlx5dv_sched_leaf_modify(mlx5dv_sched_leaf *leaf,
                                 mlx5dv_sched_attr *sched_attr)
    int mlx5dv_sched_node_destroy(mlx5dv_sched_node *node)
    int mlx5dv_sched_leaf_destroy(mlx5dv_sched_leaf *leaf)
    int mlx5dv_modify_qp_sched_elem(v.ibv_qp *qp, mlx5dv_sched_leaf *requestor,
                                    mlx5dv_sched_leaf *responder)
    int mlx5dv_reserved_qpn_alloc(v.ibv_context *context, uint32_t *qpn)
    int mlx5dv_reserved_qpn_dealloc(v.ibv_context *context, uint32_t qpn)
    void *mlx5dv_dm_map_op_addr(v.ibv_dm *dm, uint8_t op)

    # DevX APIs
    mlx5dv_devx_uar *mlx5dv_devx_alloc_uar(v.ibv_context *context,
                                           uint32_t flags)
    void mlx5dv_devx_free_uar(mlx5dv_devx_uar *devx_uar)
    int mlx5dv_devx_general_cmd(v.ibv_context *context, const void *in_,
                                size_t inlen, void *out, size_t outlen);
