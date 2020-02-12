# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved.

#cython: language_level=3

from pyverbs.base cimport PyverbsObject, PyverbsCM
cimport pyverbs.libibverbs as v

cdef class CompChannel(PyverbsCM):
    cdef v.ibv_comp_channel *cc
    cpdef close(self)
    cdef object context
    cdef add_ref(self, obj)
    cdef object cqs

cdef class CQ(PyverbsCM):
    cdef v.ibv_cq *cq
    cpdef close(self)
    cdef object context
    cdef add_ref(self, obj)
    cdef object qps
    cdef object srqs
    cdef object channel
    cdef object num_events

cdef class CqInitAttrEx(PyverbsObject):
    cdef v.ibv_cq_init_attr_ex attr
    cdef object channel

cdef class CQEX(PyverbsCM):
    cdef v.ibv_cq_ex *cq
    cdef v.ibv_cq *ibv_cq
    cpdef close(self)
    cdef object context
    cdef add_ref(self, obj)
    cdef object qps
    cdef object srqs

cdef class WC(PyverbsObject):
    cdef v.ibv_wc wc

cdef class PollCqAttr(PyverbsObject):
    cdef v.ibv_poll_cq_attr attr

cdef class WcTmInfo(PyverbsObject):
    cdef v.ibv_wc_tm_info info
