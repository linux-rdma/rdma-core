# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 HiSilicon Limited. All rights reserved.

#cython: language_level=3

from pyverbs.base cimport PyverbsObject
cimport pyverbs.providers.hns.libhns as dv
from pyverbs.device cimport Context
from pyverbs.qp cimport QP, QPEx


cdef class HnsContext(Context):
    cpdef close(self)

cdef class HnsDVContextAttr(PyverbsObject):
    cdef dv.hnsdv_context_attr attr

cdef class HnsDVContext(PyverbsObject):
    pass

cdef class HnsDVQPInitAttr(PyverbsObject):
    cdef dv.hnsdv_qp_init_attr attr

cdef class HnsQP(QPEx):
    pass
