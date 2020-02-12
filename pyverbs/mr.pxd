# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved. See COPYING file

#cython: language_level=3

from pyverbs.base cimport PyverbsCM
from . cimport libibverbs as v


cdef class MR(PyverbsCM):
    cdef object pd
    cdef v.ibv_mr *mr
    cdef int mmap_length
    cdef object is_huge
    cdef object is_user_addr
    cdef void *buf
    cpdef read(self, length, offset)

cdef class MW(PyverbsCM):
    cdef object pd
    cdef v.ibv_mw *mw

cdef class DMMR(MR):
    cdef object dm
