# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved. See COPYING file

#cython: language_level=3

from pyverbs.base cimport PyverbsCM
from . cimport libibverbs as v


cdef class MR(PyverbsCM):
    cdef object pd
    cdef v.ibv_mr *mr
    cdef void *buf
    cpdef read(self, length, offset)
    cdef add_ref(self, obj)
    cdef object bind_infos

cdef class MWBindInfo(PyverbsCM):
    cdef v.ibv_mw_bind_info info
    cdef object mr

cdef class MW(PyverbsCM):
    cdef object pd
    cdef v.ibv_mw *mw

cdef class DMMR(MR):
    cdef object dm
