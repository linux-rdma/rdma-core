# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)

#cython: language_level=3


cdef extern from 'infiniband/efadv.h':

    cpdef enum:
        EFADV_DEVICE_ATTR_CAPS_RDMA_READ
        EFADV_DEVICE_ATTR_CAPS_RNR_RETRY
        EFADV_DEVICE_ATTR_CAPS_CQ_WITH_SGID
        EFADV_DEVICE_ATTR_CAPS_RDMA_WRITE

    cpdef enum:
        EFADV_QP_DRIVER_TYPE_SRD

    cpdef enum:
        EFADV_WC_EX_WITH_SGID
