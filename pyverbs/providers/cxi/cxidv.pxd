# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2026 Hewlett Packard Enterprise Development LP

#cython: language_level=3

from pyverbs.base cimport PyverbsCM
from pyverbs.device cimport Context
cimport pyverbs.libibverbs as v
from libc.stdint cimport uint32_t

cdef extern from "infiniband/cxidv.h":
    cdef struct cxidv_lni:
        v.ibv_context *context
        uint32_t handle
        uint32_t id
        uint32_t svc_id


cdef class LNI(PyverbsCM):
    cdef cxidv_lni *lni
    cdef Context ctx
    cdef add_ref(self, obj)
    cpdef close(self)
