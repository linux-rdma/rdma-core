# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2020 Amazon.com, Inc. or its affiliates. All rights reserved.

#cython: language_level=3

cdef extern from 'infiniband/efadv.h':

    cpdef enum:
        EFADV_DEVICE_ATTR_CAPS_RDMA_READ

    cpdef enum:
        EFADV_QP_DRIVER_TYPE_SRD
