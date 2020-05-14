# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved. See COPYING file

#cython: language_level=3

from pyverbs.base cimport PyverbsObject, PyverbsCM
cimport pyverbs.librdmacm as cm


cdef class CMID(PyverbsCM):
    cdef cm.rdma_cm_id *id
    cdef object event_channel
    cdef object ctx
    cdef object pd
    cdef object mrs
    cdef add_ref(self, obj)
    cpdef close(self)


cdef class CMEventChannel(PyverbsObject):
    cdef cm.rdma_event_channel *event_channel
    cpdef close(self)


cdef class CMEvent(PyverbsObject):
    cdef cm.rdma_cm_event *event
    cpdef close(self)


cdef class AddrInfo(PyverbsObject):
    cdef cm.rdma_addrinfo *addr_info
    cpdef close(self)


cdef class ConnParam(PyverbsObject):
    cdef cm.rdma_conn_param conn_param


cdef class UDParam(PyverbsObject):
    cdef cm.rdma_ud_param ud_param

cdef class JoinMCAttrEx(PyverbsObject):
    cdef cm.rdma_cm_join_mc_attr_ex join_mc_attr_ex
