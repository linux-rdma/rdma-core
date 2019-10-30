# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved.

#cython: language_level=3


cdef extern from '<rdma/rdma_cma.h>':

    cpdef enum rdma_cm_event_type:
        RDMA_CM_EVENT_ADDR_RESOLVED
        RDMA_CM_EVENT_ADDR_ERROR
        RDMA_CM_EVENT_ROUTE_RESOLVED
        RDMA_CM_EVENT_ROUTE_ERROR
        RDMA_CM_EVENT_CONNECT_REQUEST
        RDMA_CM_EVENT_CONNECT_RESPONSE
        RDMA_CM_EVENT_CONNECT_ERROR
        RDMA_CM_EVENT_UNREACHABLE
        RDMA_CM_EVENT_REJECTED
        RDMA_CM_EVENT_ESTABLISHED
        RDMA_CM_EVENT_DISCONNECTED
        RDMA_CM_EVENT_DEVICE_REMOVAL
        RDMA_CM_EVENT_MULTICAST_JOIN
        RDMA_CM_EVENT_MULTICAST_ERROR
        RDMA_CM_EVENT_ADDR_CHANGE
        RDMA_CM_EVENT_TIMEWAIT_EXIT

    cpdef enum rdma_port_space:
        RDMA_PS_IPOIB
        RDMA_PS_TCP
        RDMA_PS_UDP
        RDMA_PS_IB

    # Hint flags which control the operation.
    cpdef enum:
        RAI_PASSIVE
        RAI_NUMERICHOST
        RAI_NOROUTE
        RAI_FAMILY
