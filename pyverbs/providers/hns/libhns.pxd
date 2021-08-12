# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 HiSilicon Limited. All rights reserved.

from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t
from libcpp cimport bool

cimport pyverbs.libibverbs as v

cdef extern from 'infiniband/hnsdv.h':

    cdef struct hnsdv_context_attr:
        uint64_t flags
        uint64_t comp_mask
        uint32_t dca_prime_qps
        uint32_t dca_unit_size
        uint64_t dca_max_size
        uint64_t dca_min_size

    cdef struct hnsdv_qp_init_attr:
        uint64_t comp_mask
        uint32_t create_flags

    bool hnsdv_is_supported(v.ibv_device *device)
    v.ibv_context* hnsdv_open_device(v.ibv_device *device,
                                     hnsdv_context_attr *attr)
    v.ibv_qp *hnsdv_create_qp(v.ibv_context *context,
                              v.ibv_qp_init_attr_ex *qp_attr,
                              hnsdv_qp_init_attr *hns_qp_attr)
