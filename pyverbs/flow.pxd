# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia All rights reserved.

#cython: language_level=3

from pyverbs.base cimport PyverbsObject, PyverbsCM
cimport pyverbs.libibverbs as v

cdef class FlowAttr(PyverbsObject):
    cdef v.ibv_flow_attr attr
    cdef object specs

cdef class Flow(PyverbsCM):
    cdef v.ibv_flow *flow
    cdef object qp
    cpdef close(self)

cdef class FlowAction(PyverbsObject):
    cdef v.ibv_flow_action *action
