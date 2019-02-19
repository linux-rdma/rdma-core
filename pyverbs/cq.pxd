# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved.
from pyverbs.base cimport PyverbsObject, PyverbsCM
cimport pyverbs.libibverbs as v

cdef class CompChannel(PyverbsCM):
    cdef v.ibv_comp_channel *cc
    cpdef close(self)
    cdef object context

cdef class CQ(PyverbsCM):
    cdef v.ibv_cq *cq
    cpdef close(self)
    cdef object context

cdef class WC(PyverbsObject):
    cdef v.ibv_wc wc
