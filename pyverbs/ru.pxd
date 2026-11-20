# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2026 Broadcom. All rights reserved.

#cython: language_level=3

from pyverbs.base cimport PyverbsCM, PyverbsObject
from pyverbs.device cimport Context
cimport pyverbs.libibverbs as v


cdef class JobAttr(PyverbsObject):
    cdef v.ibv_job_attr attr

cdef class AHAttrEx(PyverbsObject):
    cdef v.ibv_ah_attr_ex attr

cdef class QPSemantics(PyverbsObject):
    cdef v.ibv_qp_semantics semantics

cdef class Job(PyverbsCM):
    cdef v.ibv_job *job
    cdef Context ctx
    cdef object jkeys
    cdef object _is_imported
    cdef object _user_context
    cdef add_ref(self, obj)
    cpdef close(self)

cdef class JKey(PyverbsCM):
    cdef v.ibv_job_key *job_key
    cdef object pd
    cdef object job
    cpdef close(self)
