# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved. See COPYING file

from .base cimport PyverbsObject
cimport pyverbs.libibverbs as v


cdef class Context(PyverbsObject):
    cdef v.ibv_context *context
    cdef object name
    cpdef close(self)

cdef class DeviceAttr(PyverbsObject):
    cdef v.ibv_device_attr dev_attr
