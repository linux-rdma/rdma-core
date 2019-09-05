# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved.

#cython: language_level=3

from pyverbs.base cimport PyverbsObject, PyverbsCM
from . cimport libibverbs as v

cdef class SrqAttr(PyverbsObject):
    cdef v.ibv_srq_attr attr

cdef class SrqInitAttr(PyverbsObject):
    cdef v.ibv_srq_init_attr    attr

cdef class SrqInitAttrEx(PyverbsObject):
    cdef v.ibv_srq_init_attr_ex attr
    cdef object _cq
    cdef object _pd
    cdef object _xrcd

cdef class SRQ(PyverbsCM):
    cdef v.ibv_srq *srq
    cdef object cq
    cpdef close(self)
