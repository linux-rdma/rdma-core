# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2020 Amazon.com, Inc. or its affiliates. All rights reserved.

cimport pyverbs.libibverbs as v


cdef extern from 'infiniband/efadv.h':

    cdef struct efadv_device_attr:
        unsigned long           comp_mask
        unsigned int            max_sq_wr
        unsigned int            max_rq_wr
        unsigned short          max_sq_sge
        unsigned short          max_rq_sge
        unsigned short          inline_buf_size
        unsigned char           reserved[2]
        unsigned int            device_caps
        unsigned int            max_rdma_size

    int efadv_query_device(v.ibv_context *ibvctx, efadv_device_attr *attrs,
                           unsigned int inlen)
