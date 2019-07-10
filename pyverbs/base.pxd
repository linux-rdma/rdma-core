# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved.

cdef class PyverbsObject(object):
    cdef object __weakref__
    cdef object logger

cdef class PyverbsCM(PyverbsObject):
    cpdef close(self)
