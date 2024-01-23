# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2020-2024 Amazon.com, Inc. or its affiliates. All rights reserved.

#cython: language_level=3

from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t
cimport pyverbs.libibverbs as v


cdef extern from 'infiniband/efadv.h':

    cdef struct efadv_device_attr:
        uint64_t comp_mask;
        uint32_t max_sq_wr;
        uint32_t max_rq_wr;
        uint16_t max_sq_sge;
        uint16_t max_rq_sge;
        uint16_t inline_buf_size;
        uint8_t reserved[2];
        uint32_t device_caps;
        uint32_t max_rdma_size;

    cdef struct efadv_ah_attr:
        uint64_t comp_mask;
        uint16_t ahn;
        uint8_t reserved[6];

    cdef struct efadv_qp_init_attr:
        uint64_t comp_mask;
        uint32_t driver_qp_type;
        uint8_t reserved[4];

    cdef struct efadv_cq_init_attr:
        uint64_t comp_mask;
        uint64_t wc_flags;

    cdef struct efadv_cq:
        uint64_t comp_mask;

    cdef struct efadv_mr_attr:
        uint64_t comp_mask;
        uint16_t ic_id_validity;
        uint16_t recv_ic_id;
        uint16_t rdma_read_ic_id;
        uint16_t rdma_recv_ic_id;

    int efadv_query_device(v.ibv_context *ibvctx, efadv_device_attr *attrs,
                           uint32_t inlen)
    int efadv_query_ah(v.ibv_ah *ibvah, efadv_ah_attr *attr,
                       uint32_t inlen)
    v.ibv_qp *efadv_create_driver_qp(v.ibv_pd *ibvpd, v.ibv_qp_init_attr *attr,
                                     uint32_t driver_qp_type)
    v.ibv_qp *efadv_create_qp_ex(v.ibv_context *ibvctx,
                                 v.ibv_qp_init_attr_ex *attr_ex,
                                 efadv_qp_init_attr *efa_attr,
                                 uint32_t inlen)
    v.ibv_cq_ex *efadv_create_cq(v.ibv_context *ibvctx,
                                 v.ibv_cq_init_attr_ex *attr_ex,
                                 efadv_cq_init_attr *efa_attr,
                                 uint32_t inlen)
    efadv_cq *efadv_cq_from_ibv_cq_ex(v.ibv_cq_ex *ibvcqx)
    int efadv_wc_read_sgid(efadv_cq *efadv_cq, v.ibv_gid *sgid)
    int efadv_query_mr(v.ibv_mr *ibvmr, efadv_mr_attr *attr, uint32_t inlen)
