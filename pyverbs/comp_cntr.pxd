# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright Amazon.com, Inc. or its affiliates. All rights reserved.

#cython: language_level=3

from pyverbs.base cimport PyverbsObject, PyverbsCM
from pyverbs.device cimport Context
cimport pyverbs.libibverbs as v

cdef class CompCntrInitAttr(PyverbsObject):
    cdef v.ibv_comp_cntr_init_attr attr

cdef class QPAttachCompCntrAttr(PyverbsObject):
    cdef v.ibv_qp_attach_comp_cntr_attr attr

cdef class CompCntr(PyverbsCM):
    cdef v.ibv_comp_cntr *comp_cntr
    cdef Context ctx
    cpdef close(self)
