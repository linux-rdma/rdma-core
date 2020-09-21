# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2020 Amazon.com, Inc. or its affiliates. All rights reserved.

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

    int efadv_query_device(v.ibv_context *ibvctx, efadv_device_attr *attrs,
                           uint32_t inlen)
