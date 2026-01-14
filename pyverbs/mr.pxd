# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved. See COPYING file
# Copyright (c) 2020, Intel Corporation. All rights reserved. See COPYING file

#cython: language_level=3

from pyverbs.base cimport PyverbsCM, PyverbsObject
cimport pyverbs.librdmacm as cm
from . cimport libibverbs as v


cdef class MR(PyverbsCM):
    cdef object pd
    cdef object cmid
    cdef v.ibv_mr *mr
    cdef int mmap_length
    cdef object is_huge
    cdef object is_user_addr
    cdef void *buf
    cdef object _is_imported
    cdef void _allocate_buffer(self, size_t length, bint is_huge, int *mmap_length)
    cdef void _free_buffer(self, bint is_huge, int mmap_length)
    cpdef read(self, length, offset)

cdef class MREx(MR):
    cdef object dmah

cdef class MWBindInfo(PyverbsCM):
    cdef v.ibv_mw_bind_info info
    cdef object mr

cdef class MWBind(PyverbsCM):
    cdef v.ibv_mw_bind mw_bind
    cdef object mr

cdef class MW(PyverbsCM):
    cdef object pd
    cdef v.ibv_mw *mw

cdef class DMMR(MR):
    cdef object dm

cdef class DmaBufMR(MR):
    cdef object dmabuf
    cdef unsigned long offset
    cdef object is_dmabuf_internal

cdef class DmaHandleInitAttr(PyverbsObject):
    cdef v.ibv_dmah_init_attr init_attr

cdef class DMAHandle(PyverbsCM):
    cdef v.ibv_dmah *dmah
    cdef object mrs
    cdef object ctx
    cdef add_ref(self, obj)
