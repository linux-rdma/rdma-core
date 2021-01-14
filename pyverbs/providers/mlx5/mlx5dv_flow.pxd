# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

#cython: language_level=3

cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.flow cimport Flow, FlowAction
from pyverbs.base cimport PyverbsObject


cdef class Mlx5FlowMatchParameters(PyverbsObject):
    cdef dv.mlx5dv_flow_match_parameters *params
    cpdef close(self)

cdef class Mlx5FlowMatcherAttr(PyverbsObject):
    cdef dv.mlx5dv_flow_matcher_attr attr

cdef class Mlx5FlowMatcher(PyverbsObject):
    cdef dv.mlx5dv_flow_matcher *flow_matcher
    cdef object flows
    cdef add_ref(self, obj)
    cpdef close(self)

cdef class Mlx5FlowActionAttr(PyverbsObject):
    cdef dv.mlx5dv_flow_action_attr attr
    cdef object qp
    cdef object action

cdef class Mlx5Flow(Flow):
    pass

cdef class Mlx5PacketReformatFlowAction(FlowAction):
    pass
