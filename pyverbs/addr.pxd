# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved. See COPYING file

#cython: language_level=3

from .base cimport PyverbsObject, PyverbsCM
from pyverbs cimport libibverbs as v
from .cmid cimport UDParam


cdef class GID(PyverbsObject):
    cdef v.ibv_gid gid

cdef class GRH(PyverbsObject):
    cdef v.ibv_grh grh

cdef class GlobalRoute(PyverbsObject):
    cdef v.ibv_global_route gr

cdef class AHAttr(PyverbsObject):
    cdef v.ibv_ah_attr ah_attr
    cdef init_from_ud_param(self, UDParam udparam)

cdef class AH(PyverbsCM):
    cdef v.ibv_ah *ah
    cdef object pd
    cpdef close(self)
