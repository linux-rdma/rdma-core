# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved.

#cython: language_level=3

from pyverbs.base cimport PyverbsObject
from pyverbs.device cimport Context
cimport pyverbs.libibverbs as v
from .base cimport PyverbsCM


cdef class PD(PyverbsCM):
    cdef v.ibv_pd *pd
    cdef Context ctx
    cdef add_ref(self, obj)
    cdef object srqs
    cdef object mrs
    cdef object mws
    cdef object ahs
    cdef object qps
    cdef object parent_domains

cdef class ParentDomainInitAttr(PyverbsObject):
    cdef v.ibv_parent_domain_init_attr init_attr
    cdef object pd
    cdef object alloc
    cdef object dealloc

cdef class ParentDomain(PD):
    cdef object protection_domain
    pass

cdef class ParentDomainContext(PyverbsObject):
    cdef object p_alloc
    cdef object p_free
    cdef object pd
