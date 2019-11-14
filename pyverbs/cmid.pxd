# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved. See COPYING file

#cython: language_level=3

from pyverbs.base cimport PyverbsObject, PyverbsCM
from libc.string cimport memcpy, memset
from libc.stdlib cimport free, malloc
cimport pyverbs.librdmacm as cm


cdef class CMID(PyverbsCM):
    cdef cm.rdma_cm_id *id
    cdef object ctx
    cdef object pd
    cpdef close(self)


cdef class AddrInfo(PyverbsObject):
    cdef cm.rdma_addrinfo *addr_info
    cpdef close(self)


cdef class ConnParam(PyverbsObject):
    cdef cm.rdma_conn_param conn_param
